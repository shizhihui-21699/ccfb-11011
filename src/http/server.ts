/**
 * Request router and TLS listener.
 *
 * Every request is gated on a valid device certificate before routing. The TLS
 * layer is configured with `requestCert: true, rejectUnauthorized: false` so a
 * missing or untrusted certificate reaches this code and can be answered with
 * an auditable 401, rather than failing the handshake with no record.
 */
import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import type { Config } from '../config.ts';
import type { Runtime } from '../core/runtime.ts';
import {
  readServerCertificate,
  verifyClientCertificate,
  type ClientIdentity,
} from '../pki/trust.ts';
import {
  clientIp,
  redirect,
  sendHtml,
  sendJson,
  sendText,
  setSecurityHeaders,
} from './respond.ts';
import { handleLogin, handleLogout, resolveSession, SESSION_COOKIE } from './auth.ts';
import { denyApp, serveApp } from './proxy.ts';
import { consolePage, type ConsoleAppView } from './views/console.ts';
import {
  adminAuditPage,
  adminDevicesPage,
  adminOverviewPage,
  adminPolicyPage,
  adminSessionsPage,
  type AdminContext,
} from './views/admin.ts';
import { unauthenticatedPage } from './views/errors.ts';

export interface ServerHandle {
  server: https.Server;
  port: number;
  url: string;
  close(): Promise<void>;
}

export interface StartOptions {
  runtime: Runtime;
  port?: number;
  host?: string;
  /** Path to TLS material; defaults to the runtime's pki dir. */
  pkiDir?: string;
}

export async function startServer(options: StartOptions): Promise<ServerHandle> {
  const runtime = options.runtime;
  const tls = readServerCertificate(options.pkiDir ?? runtime.config.pkiDir);
  // The device CA is advertised so well-behaved clients can complete a
  // certificate chain. Node's TLS layer deliberately does NOT reject here:
  // verification happens per request in `verifyClientCertificate`, which lets
  // an invalid certificate produce an auditable 401 rather than a bare
  // handshake failure.
  const ca = runtime.trust.deviceCaPem;

  const server = https.createServer(
    {
      cert: tls.cert,
      key: tls.key,
      ca,
      requestCert: true,
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
      ciphers: undefined,
      honorCipherOrder: true,
    },
    (req, res) => {
      void handleRequest(runtime, req, res).catch((error: unknown) => {
        runtime.logger('http.error', {
          error: error instanceof Error ? error.message : String(error),
          path: req.url,
        });
        if (!res.headersSent) sendText(res, 500, 'internal error');
        else res.end();
      });
    },
  );

  const port = options.port ?? runtime.config.port;
  const host = options.host ?? runtime.config.host;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve());
  });
  const address = server.address() as AddressInfo;
  const url = `https://${host === '0.0.0.0' ? '127.0.0.1' : host}:${address.port}`;

  return {
    server,
    port: address.port,
    url,
    async close() {
      server.closeAllConnections?.();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

async function handleRequest(
  runtime: Runtime,
  req: http.IncomingMessage,
  res: http.ServerResponse,
): Promise<void> {
  const ip = clientIp(req, runtime.config.trustProxy);
  const url = new URL(req.url ?? '/', runtime.config.publicOrigin);

  // ---- Layer 1: device certificate -------------------------------------
  const peer = (req.socket as import('node:tls').TLSSocket).getPeerX509Certificate?.();
  const check = peer === undefined ? null : verifyClientCertificate(peer, runtime.trust);
  if (check === null || !check.ok || check.identity === null) {
    const detail = check?.detail ?? 'TLS connection presented no client certificate';
    const failure = check?.failure ?? 'no_certificate';
    runtime.audit.append({
      actorType: 'device',
      actorId: 'unknown',
      action: 'mtls.rejected',
      decision: 'deny',
      reason: detail,
      ip,
      detail: { failure, path: url.pathname.slice(0, 200) },
    });
    // Drain the body so the client sees the response rather than a reset.
    req.resume();
    sendHtml(res, 401, unauthenticatedPage({ reason: detail, failure }));
    return;
  }
  const device: ClientIdentity = check.identity;

  // ---- Layer 2: routes --------------------------------------------------
  const pathname = url.pathname;

  if (req.method === 'GET' && (pathname === '/' || pathname === '/console')) {
    return handleConsole(runtime, req, res, device);
  }
  if (pathname === '/login') return handleLogin(runtime, req, res, device);
  if (pathname === '/logout' && req.method === 'POST') {
    const session = resolveSession(runtime, req, device, ip);
    if (session === null) {
      res.setHeader('set-cookie', `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure`);
      return redirect(res, '/login');
    }
    return handleLogout(runtime, req, res, session);
  }
  if (pathname === '/healthz') return sendJson(res, 200, healthPayload(runtime));
  if (pathname === '/admin' || pathname.startsWith('/admin/')) {
    return handleAdmin(runtime, req, res, device, pathname, url);
  }
  if (pathname.startsWith('/app/')) {
    return handleApp(runtime, req, res, device, pathname);
  }
  return sendHtml(res, 404, unauthenticatedPage({ reason: 'No such page.', failure: null }));
}

function healthPayload(runtime: Runtime): Record<string, unknown> {
  const chain = runtime.audit.verify();
  return {
    status: chain.ok ? 'ok' : 'degraded',
    devices: runtime.devices.list().filter((device) => device.status === 'enrolled').length,
    sessions: runtime.sessions.countActive(),
    grants: runtime.grants.countActive(),
    audit: { ok: chain.ok, records: chain.records },
    lastRevalidation: runtime.revalidator.getLastReport(),
    posture: runtime.postureSync?.getStatus() ?? null,
  };
}

// ---- Console ------------------------------------------------------------

function handleConsole(
  runtime: Runtime,
  req: http.IncomingMessage,
  res: http.ServerResponse,
  device: ClientIdentity,
): void {
  const ip = clientIp(req, runtime.config.trustProxy);
  const session = resolveSession(runtime, req, device, ip);
  if (session === null) return redirect(res, '/login');
  const user = runtime.users.findById(session.userId);
  if (user === null) return redirect(res, '/login');

  const deviceRecord = runtime.devices.findById(device.deviceId);
  if (deviceRecord === null) return redirect(res, '/login');
  const grantViews: ConsoleAppView[] = runtime.config.apps.map((app) => {
    const grant = runtime.grants.findBySessionApp(session.id, app.id);
    const decision = runtime.access.decide(
      { user, device: deviceRecord, appId: app.id, now: new Date() },
      runtime.policy.get().current,
    );
    if (grant !== null && decision.allow) {
      return {
        app,
        status: 'granted',
        detail: 'Session grant is active.',
        requirements: decision.requirements,
        grantExpiresAt: grant.expiresAt,
      };
    }
    return {
      app,
      status: decision.allow ? 'available' : 'denied',
      detail: decision.reason,
      requirements: decision.requirements,
      grantExpiresAt: null,
    };
  });

  const nonce = crypto.randomBytes(16).toString('base64url');
  setSecurityHeaders(res, nonce);
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(
    consolePage({
      nonce,
      user,
      session,
      device,
      apps: grantViews,
      posture: runtime.posture.get(device.deviceId),
      revalidateSeconds: Math.round(runtime.config.thresholds.revalidateIntervalMs / 1000),
    }),
  );
}

// ---- Application proxy --------------------------------------------------

function handleApp(
  runtime: Runtime,
  req: http.IncomingMessage,
  res: http.ServerResponse,
  device: ClientIdentity,
  pathname: string,
): void {
  const ip = clientIp(req, runtime.config.trustProxy);
  const session = resolveSession(runtime, req, device, ip);
  if (session === null) {
    // Preserve the target so the user lands back after signing in.
    const next = encodeURIComponent(pathname + (req.url?.includes('?') ? req.url.slice(req.url.indexOf('?')) : ''));
    return redirect(res, `/login?next=${next}`);
  }
  const user = runtime.users.findById(session.userId);
  const deviceRecord = runtime.devices.findById(device.deviceId);
  if (user === null || deviceRecord === null) return redirect(res, '/login');

  const match = /^\/app\/([a-z0-9-]+)(\/.*)?$/.exec(pathname);
  if (!match) return sendText(res, 404, 'unknown application');
  const appId = match[1]!;
  const rest = match[2] ?? '/';
  const app = runtime.config.apps.find((entry) => entry.id === appId);
  if (app === undefined) return sendText(res, 404, 'unknown application');

  // Re-check live so a grant revoked between ticks cannot be used.
  const existing = runtime.grants.findBySessionApp(session.id, appId);
  if (existing !== null) {
    const live = runtime.revalidator.checkGrantNow(existing.id);
    if (!live.ok) {
      // Show the same structured detail as a fresh policy denial, so the user
      // can see which requirement broke rather than a bare "revoked".
      const recheck = runtime.access.decide(
        { user, device: deviceRecord, appId, now: new Date() },
        runtime.policy.get().current,
      );
      req.resume();
      return denyApp(runtime, app, req, res, session, device, {
        code: live.code,
        reason: live.reason,
        ruleId: recheck.ruleId,
        requirements: recheck.requirements,
      });
    }
  }

  const decision = runtime.access.decide({ user, device: deviceRecord, appId, now: new Date() }, runtime.policy.get().current);
  if (!decision.allow) {
    req.resume();
    return denyApp(runtime, app, req, res, session, device, decision);
  }
  runtime.sessionManager.createGrant(session, appId, decision, new Date());
  serveApp({ runtime }, app, req, res, { session, device, appPath: rest });
}

// ---- Admin --------------------------------------------------------------

function handleAdmin(
  runtime: Runtime,
  req: http.IncomingMessage,
  res: http.ServerResponse,
  device: ClientIdentity,
  pathname: string,
  url: URL,
): void {
  const ip = clientIp(req, runtime.config.trustProxy);
  const session = resolveSession(runtime, req, device, ip);
  if (session === null) return redirect(res, '/login');
  const user = runtime.users.findById(session.userId);
  if (user === null || !user.roles.includes('admin')) {
    runtime.audit.append({
      actorType: 'user',
      actorId: session.userId,
      action: 'admin.access',
      decision: 'deny',
      reason: 'User does not hold the admin role.',
      sessionId: session.id,
      deviceId: device.deviceId,
      userId: session.userId,
      ip,
      detail: { path: pathname },
    });
    return sendHtml(res, 403, unauthenticatedPage({ reason: 'Administrator role required.', failure: null }));
  }

  const policy = runtime.policy.get();
  const context: AdminContext = {
    nonce: crypto.randomBytes(16).toString('base64url'),
    runtime: {
      config: runtime.config as Config,
      users: runtime.users.list(),
      devices: runtime.devices.list(),
      sessions: runtime.sessions.listActive(),
      grants: runtime.grants.listActive(),
      posture: runtime.posture.list(),
      auditRecords:
        pathname === '/admin/audit'
          ? runtime.audit.recent(200, {
              ...(url.searchParams.get('action') ? { action: url.searchParams.get('action')! } : {}),
              ...(url.searchParams.get('deviceId') ? { deviceId: url.searchParams.get('deviceId')! } : {}),
              ...(url.searchParams.get('decision') ? { decision: url.searchParams.get('decision')! } : {}),
            })
          : runtime.audit.recent(12),
      policy: policy.current,
      policyUpdatedAt: policy.updatedAt,
      policyLoadError: policy.loadError,
      chain: runtime.audit.verify(),
      revalidation: runtime.revalidator.getLastReport(),
      postureStatus: runtime.postureSync?.getStatus() ?? null,
      revalidationIntervalMs: runtime.config.thresholds.revalidateIntervalMs,
      postureMaxAgeSeconds: runtime.config.thresholds.postureMaxAgeSeconds,
    },
  };

  let html: string;
  if (pathname === '/admin' || pathname === '/admin/') {
    html = adminOverviewPage(context);
  } else if (pathname === '/admin/devices') {
    html = adminDevicesPage(context);
  } else if (pathname === '/admin/policy') {
    html = adminPolicyPage(context, runtime.config.apps);
  } else if (pathname === '/admin/sessions') {
    html = adminSessionsPage(context);
  } else if (pathname === '/admin/audit') {
    html = adminAuditPage(context, {
      action: url.searchParams.get('action'),
      deviceId: url.searchParams.get('deviceId'),
      decision: url.searchParams.get('decision'),
    });
  } else if (pathname === '/admin/audit/export') {
    setSecurityHeaders(res);
    res.writeHead(200, {
      'content-type': 'application/x-ndjson; charset=utf-8',
      'content-disposition': 'attachment; filename="audit.jsonl"',
    });
    res.end(runtime.audit.toJsonl());
    return;
  } else {
    return sendText(res, 404, 'not found');
  }

  const nonce = context.nonce;
  setSecurityHeaders(res, nonce);
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(html);
}
