/**
 * Authenticated reverse proxy for internal applications.
 *
 * `/app/<appId>/...` is relayed to the configured upstream. Before any byte
 * reaches the upstream, the request goes through:
 *
 *   1. session validity (cookie sealed to this device certificate),
 *   2. grant lookup, creating one only on a fresh allow decision,
 *   3. a live re-check (`checkGrantNow`) so a grant revoked by the background
 *      loop cannot be used even in the window before the next pass.
 *
 * Upstream requests are rewritten to a `/app/<id>/...` prefix so absolute
 * links in the upstream can be fixed up by the response rewriter. Responses
 * are streamed, with hop-by-hop headers stripped, identity headers injected,
 * and the proxied origin's cookies rewritten to a per-app path.
 */
import http from 'node:http';
import https from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Runtime } from '../core/runtime.ts';
import type { ClientIdentity } from '../pki/trust.ts';
import type { SessionRecord } from '../store/types.ts';
import type { AppDefinition } from '../config.ts';
import { clientIp, sendHtml, sendJson, sendText } from './respond.ts';
import { accessDeniedPage } from './views/console.ts';

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

export interface ProxyDeps {
  runtime: Runtime;
}

/**
 * Streams a request to an upstream application. Resolves once the response has
 * been handed off; rejects on connection errors before headers arrive.
 */
export function forwardRequest(
  deps: ProxyDeps,
  app: AppDefinition,
  req: IncomingMessage,
  res: ServerResponse,
  context: { session: SessionRecord; device: ClientIdentity; appPath: string },
): void {
  const runtime = deps.runtime;
  const upstreamUrl = new URL(app.upstream);
  const targetPath = `${trimTrailingSlash(upstreamUrl.pathname)}${context.appPath}`;
  const target = new URL(targetPath === '' ? '/' : targetPath, upstreamUrl);
  if (req.url !== undefined && req.url.includes('?')) {
    const query = req.url.slice(req.url.indexOf('?') + 1);
    target.search = query;
  }

  const headers = buildUpstreamHeaders(req, context);
  const isHttps = upstreamUrl.protocol === 'https:';
  const transport = isHttps ? https : http;

  const upstreamRequest = transport.request(
    {
      protocol: upstreamUrl.protocol,
      hostname: upstreamUrl.hostname,
      port: upstreamUrl.port === '' ? (isHttps ? 443 : 80) : upstreamUrl.port,
      method: req.method,
      path: `${target.pathname}${target.search}`,
      headers,
      timeout: 30_000,
    },
    (upstreamResponse) => {
      if (
        !runtime.config.apps.some((entry) => entry.id === app.id) ||
        runtime.devices.findById(context.device.deviceId)?.status !== 'enrolled'
      ) {
        // Re-checked at response time: a device revoked while the upstream was
        // responding must not receive the body.
        res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('Access revoked');
        return;
      }
      relayResponse(res, upstreamResponse, app);
    },
  );

  upstreamRequest.on('timeout', () => {
    runtime.audit.append({
      actorType: 'system',
      actorId: 'proxy',
      action: 'app.upstream_timeout',
      decision: 'deny',
      reason: `Upstream ${app.id} did not respond within 30s.`,
      appId: app.id,
      sessionId: context.session.id,
      deviceId: context.device.deviceId,
      userId: context.session.userId,
      detail: { upstream: app.upstream },
    });
    if (!res.headersSent) sendText(res, 504, 'Upstream application timed out.');
    upstreamRequest.destroy();
  });

  upstreamRequest.on('error', (error) => {
    runtime.audit.append({
      actorType: 'system',
      actorId: 'proxy',
      action: 'app.upstream_error',
      decision: 'deny',
      reason: `Upstream ${app.id} failed: ${error.message}`,
      appId: app.id,
      sessionId: context.session.id,
      deviceId: context.device.deviceId,
      userId: context.session.userId,
    });
    if (!res.headersSent) sendText(res, 502, 'Upstream application unavailable.');
  });

  req.pipe(upstreamRequest);
  req.on('aborted', () => upstreamRequest.destroy());
}

function buildUpstreamHeaders(
  req: IncomingMessage,
  context: { session: SessionRecord; device: ClientIdentity; appPath: string },
): http.OutgoingHttpHeaders {
  const headers: http.OutgoingHttpHeaders = {};
  for (const [name, value] of Object.entries(req.headers)) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || lower === 'host' || lower === 'cookie' || lower === 'authorization') continue;
    if (value !== undefined) headers[lower] = value;
  }
  headers['x-forwarded-for'] = context.session.ip;
  headers['x-forwarded-proto'] = 'https';
  headers['x-forwarded-host'] = req.headers.host ?? '';
  headers['x-zt-user-id'] = context.session.userId;
  headers['x-zt-device-id'] = context.device.deviceId;
  headers['x-zt-session-id'] = context.session.id;
  headers['x-zt-forwarded-path'] = context.appPath;
  return headers;
}

function relayResponse(
  res: ServerResponse,
  upstream: http.IncomingMessage,
  app: AppDefinition,
): void {
  const headers: http.OutgoingHttpHeaders = {};
  for (const [name, value] of Object.entries(upstream.headers)) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower)) continue;
    if (lower === 'set-cookie' && Array.isArray(value)) {
      headers[lower] = value.map((cookie) => rewriteCookiePath(String(cookie), app.id));
      continue;
    }
    if (lower === 'set-cookie' && typeof value === 'string') {
      headers[lower] = rewriteCookiePath(value, app.id);
      continue;
    }
    if (lower === 'content-security-policy') continue; // upstream CSP would break the prefix
    if (lower === 'location' && typeof value === 'string') {
      headers[lower] = rewriteLocation(value, app.id);
      continue;
    }
    headers[lower] = value as string | string[];
  }
  headers['x-zt-proxied-by'] = 'zero-trust-access-proxy';
  res.writeHead(upstream.statusCode ?? 502, headers);
  upstream.pipe(res);
  upstream.on('error', () => res.destroy());
}

function trimTrailingSlash(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

/** Rewrites an upstream Location to stay inside the `/app/<id>` namespace. */
export function rewriteLocation(location: string, appId: string): string {
  if (location.startsWith('/')) {
    if (location.startsWith(`/app/${appId}/`) || location === `/app/${appId}`) return location;
    return `/app/${appId}${location}`;
  }
  return location.replace(/^https?:\/\/[^/]+/, '');
}

/** Scopes upstream cookies to this app's proxy path. */
export function rewriteCookiePath(cookie: string, appId: string): string {
  const withoutPath = cookie.replace(/;\s*Path=[^;]*/i, '').replace(/;\s*Secure/i, '');
  return `${withoutPath}; Path=/app/${appId}/; Secure; SameSite=Lax`;
}

/**
 * Serves a proxied application request after authorization. Caller must have
 * already validated the session cookie and resolved the grant.
 */
export function serveApp(
  deps: ProxyDeps,
  app: AppDefinition,
  req: IncomingMessage,
  res: ServerResponse,
  context: { session: SessionRecord; device: ClientIdentity; appPath: string },
): void {
  const runtime = deps.runtime;
  runtime.audit.append({
    actorType: 'user',
    actorId: context.session.userId,
    action: 'app.request',
    decision: 'allow',
    reason: `Granted access to ${app.name}.`,
    appId: app.id,
    sessionId: context.session.id,
    deviceId: context.device.deviceId,
    userId: context.session.userId,
    ip: context.session.ip,
    detail: { path: context.appPath.slice(0, 200), method: req.method },
  });
  forwardRequest(deps, app, req, res, context);
}

/** Renders a policy denial page and records the decision. */
export function denyApp(
  runtime: Runtime,
  app: AppDefinition,
  req: IncomingMessage,
  res: ServerResponse,
  session: SessionRecord,
  device: ClientIdentity,
  decision: { code: string; reason: string; ruleId: string | null; requirements: { name: string; ok: boolean; detail: string }[] },
): void {
  runtime.audit.append({
    actorType: 'user',
    actorId: session.userId,
    action: 'app.access',
    decision: 'deny',
    reason: decision.reason,
    appId: app.id,
    sessionId: session.id,
    deviceId: device.deviceId,
    userId: session.userId,
    ip: clientIp(req, runtime.config.trustProxy),
    detail: { code: decision.code, ruleId: decision.ruleId, requirements: decision.requirements },
  });
  sendHtml(
    res,
    403,
    accessDeniedPage({
      app,
      code: decision.code,
      reason: decision.reason,
      requirements: decision.requirements,
      session,
    }),
  );
}

export { sendJson };
