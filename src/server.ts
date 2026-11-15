/**
 * Zero-trust access proxy.
 *
 * Request pipeline:
 *   1. TLS: client certificate presented and verified against our CA.
 *   2. Identity: device id from the certificate SAN URI, user id from the
 *      authenticated session.
 *   3. Policy: host + path select an application; user/group and posture
 *      requirements are evaluated against data pulled from the posture service.
 *   4. Proxy: allowed requests stream upstream with identity headers.
 *
 * A background enforcer re-evaluates live sessions on a fixed interval, so a
 * device that degrades loses its session inside the revocation SLA even if it
 * sends no further traffic.
 */
import { createServer as createHttpsServer } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import type { TLSSocket } from 'node:tls';
import { loadPolicy, loadServiceConfig, type ServiceConfig } from './config.ts';
import { AuditLog } from './audit.ts';
import { createLogger } from './log.ts';
import { DeviceStore } from './stores/deviceStore.ts';
import { UserStore } from './stores/userStore.ts';
import { HttpPostureSource, PostureCache } from './posture/cache.ts';
import { PolicyEngine } from './policy/engine.ts';
import { SessionStore } from './auth/sessionStore.ts';
import { RateLimiter } from './auth/rateLimit.ts';
import { extractDeviceIdentity, fingerprintMatches, CertIdentityError } from './auth/deviceIdentity.ts';
import { SessionEnforcer } from './enforcement.ts';
import { proxyRequest } from './http/proxy.ts';
import {
  HttpError,
  clientIp,
  escapeHtml,
  readForm,
  safeRedirectPath,
  sendHtml,
  sendJson,
  sendText,
} from './http/httpUtil.ts';
import {
  layout,
  pageHeader,
  renderApps,
  renderAudit,
  renderDeviceTable,
  renderSessions,
  describeRequirements,
  type DeviceRowView,
} from './views.ts';
import type { DenialReason, DeviceIdentity, DeviceRecord, SessionRecord, AuthenticatedUser } from './types.ts';
import {
  normalizeHost,
  parseCookies,
  randomId,
  randomToken,
  resolveRequestPath,
  safeEqual,
  truncate,
} from './util.ts';

const log = createLogger('proxy');

export const CONTROL_PREFIX = '/_zta';
export const SESSION_COOKIE = '__Host-zta_session';
export const CSRF_COOKIE = '__Host-zta_csrf';

export interface AppContext {
  config: ServiceConfig;
  policy: PolicyEngine;
  users: UserStore;
  devices: DeviceStore;
  sessions: SessionStore;
  posture: PostureCache;
  audit: AuditLog;
  enforcer: SessionEnforcer;
  loginLimiter: RateLimiter;
  startedAt: number;
}

export function buildContext(config: ServiceConfig): AppContext {
  const policy = new PolicyEngine(loadPolicy(config.policyFile));
  const users = new UserStore(config.usersFile, createLogger('users'));
  const devices = new DeviceStore(config.devicesFile);
  devices.load();

  const audit = new AuditLog({ filePath: config.auditFile });
  const sessions = new SessionStore({
    ttlMs: policy.settings.sessionTtlMinutes * 60_000,
    idleMs: policy.settings.idleTimeoutMinutes * 60_000,
  });
  sessions.onRevoke = (record) => {
    log.info('session revoked', { sessionId: record.id, deviceId: record.deviceId, reason: record.revokeReason });
  };

  const posture = new PostureCache({
    source: new HttpPostureSource(config.postureServiceUrl, config.postureToken, 3_000, createLogger('posture-client')),
    ttlMs: policy.settings.postureCacheSeconds * 1000,
    log: createLogger('posture-cache'),
  });

  const enforcer = new SessionEnforcer({
    intervalMs: policy.settings.postureRecheckSeconds * 1000,
    policy,
    devices,
    users,
    posture,
    sessions,
    audit,
    log: createLogger('enforcer'),
  });

  return {
    config,
    policy,
    users,
    devices,
    sessions,
    posture,
    audit,
    enforcer,
    loginLimiter: new RateLimiter(policy.settings.loginRateLimit),
    startedAt: Date.now(),
  };
}

// ---------------------------------------------------------------------------
// Cookie + identity helpers
// ---------------------------------------------------------------------------

export function sessionCookie(token: string, maxAgeSeconds: number): string {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Strict`;
}

export function clearedSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

export function peerIdentity(req: IncomingMessage): { identity?: DeviceIdentity; error?: string } {
  const socket = req.socket as TLSSocket;
  if (!socket.authorized) {
    const error = socket.authorizationError;
    return { error: error ? String(error) : 'client certificate could not be verified' };
  }
  const cert = socket.getPeerCertificate(false);
  if (!cert || Object.keys(cert).length === 0) return { error: 'client certificate is required' };
  try {
    return { identity: extractDeviceIdentity(cert) };
  } catch (error) {
    return { error: error instanceof CertIdentityError ? error.message : 'invalid client certificate' };
  }
}

interface AuthContext {
  session: SessionRecord;
  user: AuthenticatedUser;
}

function authenticate(ctx: AppContext, req: IncomingMessage): AuthContext | null {
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (!token) return null;
  const resolved = ctx.sessions.resolve(token);
  if (!resolved.ok) {
    ctx.audit.record({
      event: 'access.deny',
      outcome: 'deny',
      actor: { ip: clientIp(req) },
      reasonCodes: [`session.${resolved.reason}`],
      message: `session rejected: ${resolved.reason}`,
      detail: { path: truncate(req.url ?? '', 160) },
    });
    return null;
  }
  const session = resolved.record;
  const user = ctx.users.get(session.userId);
  if (!user) {
    ctx.sessions.revokeRecord(session, 'user_unknown');
    return null;
  }
  return { session, user };
}

/**
 * Authenticate plus verify that this request's TLS certificate is the same
 * certificate the session was created with. Prevents session cookie replay
 * from a different machine holding a valid but different device cert.
 */
function authenticateWithCert(ctx: AppContext, req: IncomingMessage): AuthContext | null {
  const auth = authenticate(ctx, req);
  if (!auth) return null;
  const peer = peerIdentity(req);
  if (!peer.identity) {
    ctx.audit.record({
      event: 'access.deny',
      outcome: 'deny',
      actor: { userId: auth.user.id, deviceId: auth.session.deviceId, ip: clientIp(req) },
      sessionId: auth.session.id,
      reasonCodes: ['device.cert_invalid'],
      message: peer.error,
    });
    return null;
  }
  if (!fingerprintMatches(peer.identity.fingerprint256, auth.session.certFingerprint256)) {
    ctx.audit.record({
      event: 'access.deny',
      outcome: 'deny',
      actor: { userId: auth.user.id, deviceId: peer.identity.deviceId, ip: clientIp(req) },
      sessionId: auth.session.id,
      reasonCodes: ['session.cert_mismatch'],
      message: 'presented certificate does not match the session certificate',
    });
    ctx.sessions.revokeRecord(auth.session, 'cert_mismatch');
    return null;
  }
  if (peer.identity.deviceId !== auth.session.deviceId) {
    ctx.audit.record({
      event: 'access.deny',
      outcome: 'deny',
      actor: { userId: auth.user.id, deviceId: peer.identity.deviceId, ip: clientIp(req) },
      sessionId: auth.session.id,
      reasonCodes: ['session.device_mismatch'],
      message: 'presented certificate device id does not match the session',
    });
    ctx.sessions.revokeRecord(auth.session, 'device_mismatch');
    return null;
  }
  return auth;
}

function verifyCsrf(req: IncomingMessage, submitted: string | null | undefined, session: SessionRecord): boolean {
  const cookie = parseCookies(req.headers.cookie)[CSRF_COOKIE];
  const token = submitted ?? cookie ?? '';
  return Boolean(token) && safeEqual(session.csrfToken, token);
}

function redirect(res: ServerResponse, location: string, extra: Record<string, string | string[]> = {}): void {
  if (res.headersSent) return;
  res.writeHead(302, { location, 'cache-control': 'no-store', ...extra });
  res.end();
}

function page(res: ServerResponse, status: number, title: string, body: string): void {
  sendHtml(res, status, layout(title, body));
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

function loginPageBody(nextPath: string, csrf: string, notice?: { text: string; kind: 'ok' | 'bad' }): string {
  return `<main>
  <section>
    <h2>Zero-trust access proxy</h2>
    <div class="pad">
      ${
        notice
          ? `<div class="banner ${notice.kind}">${escapeHtml(notice.text)}</div><div style="height:14px"></div>`
          : ''
      }
      <p class="muted">Sign in with your directory account. This connection must present a device
      certificate issued by the corporate CA whose device id is enrolled and assigned to you.</p>
      <form method="post" action="${CONTROL_PREFIX}/login">
        <input type="hidden" name="next" value="${escapeHtml(nextPath)}">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
        <p><label>User id<br><input name="username" autocomplete="username" required
            style="width:min(320px,100%);padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--fg)"></label></p>
        <p><label>Password<br><input name="password" type="password" autocomplete="current-password" required
            style="width:min(320px,100%);padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--fg)"></label></p>
        <p><button type="submit">Sign in</button></p>
      </form>
    </div>
  </section>
</main>`;
}

function describePeer(peer: { identity?: DeviceIdentity; error?: string }): { text: string; kind: 'ok' | 'bad' } {
  return peer.identity
    ? { text: `Device certificate presented: ${peer.identity.deviceId} (${peer.identity.subject})`, kind: 'ok' }
    : { text: `No usable client certificate on this connection: ${peer.error ?? 'not presented'}`, kind: 'bad' };
}

function handleLoginGet(ctx: AppContext, req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url ?? '/', 'https://placeholder');
  const nextPath = safeRedirectPath(url.searchParams.get('next'));
  const existing = authenticate(ctx, req);
  if (existing) {
    // Only bounce an existing session onward when this connection carries the
    // certificate it was created with; otherwise the browser would loop
    // between the console and the sign-in page.
    const peer = peerIdentity(req);
    const certOk =
      peer.identity !== undefined &&
      fingerprintMatches(peer.identity.fingerprint256, existing.session.certFingerprint256) &&
      peer.identity.deviceId === existing.session.deviceId;
    if (certOk) {
      redirect(res, nextPath === '/' ? `${CONTROL_PREFIX}/` : nextPath);
      return;
    }
    redirect(res, `${CONTROL_PREFIX}/login`, { 'set-cookie': clearedSessionCookie() });
    return;
  }
  const csrf = randomToken(24);
  const body = loginPageBody(nextPath, csrf, describePeer(peerIdentity(req)));
  sendHtml(res, 200, layout('Sign in', body), {
    'set-cookie': `${CSRF_COOKIE}=${encodeURIComponent(csrf)}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Strict`,
  });
}

async function handleLoginPost(ctx: AppContext, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const form = await readForm(req, 8 * 1024);
  const nextPath = safeRedirectPath(form.get('next'));
  const username = (form.get('username') ?? '').trim().toLowerCase();
  const password = form.get('password') ?? '';
  const ip = clientIp(req);
  const csrf = form.get('csrf') ?? '';
  const cookieCsrf = parseCookies(req.headers.cookie)[CSRF_COOKIE] ?? '';

  const rerender = (notice: { text: string; kind: 'ok' | 'bad' }, status = 200) => {
    const fresh = randomToken(24);
    sendHtml(res, status, layout('Sign in', loginPageBody(nextPath, fresh, notice)), {
      'set-cookie': `${CSRF_COOKIE}=${encodeURIComponent(fresh)}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Strict`,
    });
  };

  if (!csrf || !cookieCsrf || !safeEqual(csrf, cookieCsrf)) {
    rerender({ text: 'Your sign-in form expired. Please submit it again.', kind: 'bad' }, 400);
    return;
  }

  const peer = peerIdentity(req);
  const rateKey = `${username}|${peer.identity?.deviceId ?? ip}`;
  const limit = ctx.loginLimiter.check(rateKey);
  if (!limit.allowed) {
    ctx.audit.record({
      event: 'auth.login.rate_limited',
      outcome: 'deny',
      actor: { userId: username, deviceId: peer.identity?.deviceId, ip },
      reasonCodes: ['auth.rate_limited'],
      message: 'too many failed sign-in attempts',
      detail: { retryAfterSeconds: limit.retryAfterSeconds },
    });
    res.setHeader('retry-after', String(limit.retryAfterSeconds ?? 60));
    rerender({ text: 'Too many failed attempts. Try again in a few minutes.', kind: 'bad' }, 429);
    return;
  }

  if (!peer.identity) {
    ctx.loginLimiter.recordFailure(rateKey);
    ctx.audit.record({
      event: 'auth.login.denied',
      outcome: 'deny',
      actor: { userId: username, ip },
      reasonCodes: ['device.cert_missing'],
      message: peer.error ?? 'no client certificate',
    });
    rerender({ text: `Device check failed: ${peer.error ?? 'client certificate required'}`, kind: 'bad' }, 401);
    return;
  }
  const identity = peer.identity;

  const deny = (status: number, codes: string[], message: string, detail?: Record<string, unknown>) => {
    ctx.loginLimiter.recordFailure(rateKey);
    ctx.audit.record({
      event: 'auth.login.denied',
      outcome: 'deny',
      actor: { userId: username, deviceId: identity.deviceId, ip },
      reasonCodes: codes,
      message,
      detail: { subject: identity.subject, ...detail },
    });
    rerender({ text: message, kind: 'bad' }, status);
  };

  const device = ctx.devices.get(identity.deviceId);
  if (!device) {
    deny(403, ['device.not_enrolled'], `Device ${identity.deviceId} is not enrolled. Contact IT to enroll it.`);
    return;
  }
  if (device.status !== 'active') {
    deny(403, ['device.revoked'], `Device ${identity.deviceId} has been revoked.`);
    return;
  }
  if (!fingerprintMatches(identity.fingerprint256, device.certFingerprint256)) {
    deny(
      403,
      ['device.cert_not_enrolled'],
      'The certificate on this connection is not the one enrolled for this device.',
      { presented: identity.fingerprint256, enrolled: device.certFingerprint256 },
    );
    return;
  }

  const auth = ctx.users.authenticate(username, password);
  if (!auth.ok || !auth.user) {
    deny(401, ['auth.bad_credentials'], 'Invalid user id or password.');
    return;
  }
  const user = auth.user;
  // Same binding rule the policy engine applies per request; honour the
  // setting here too so sign-in and request-time checks cannot disagree.
  if (ctx.policy.settings.requireDeviceAssignedToUser && device.assignedTo !== user.id) {
    deny(403, ['device.not_assigned_to_user'], `Device ${identity.deviceId} is not assigned to ${user.id}.`, {
      assignedTo: device.assignedTo,
    });
    return;
  }

  // Posture gate at the door. A device that fails the baseline cannot even
  // establish a session.
  const snapshot = await ctx.posture.get(device.id);
  const evaluation = ctx.policy.evaluateDevicePosture(device, snapshot.record?.facts ?? null);
  if (!evaluation.passed) {
    const reasons: DenialReason[] = evaluation.reasons;
    ctx.audit.record({
      event: 'device.check.fail',
      outcome: 'deny',
      actor: { userId: user.id, deviceId: device.id, ip },
      reasonCodes: reasons.map((reason) => reason.code),
      message: reasons.map((reason) => reason.message).join('; '),
      detail: {
        stage: 'login',
        postureStatus: evaluation.status,
        score: evaluation.score,
        fetchError: snapshot.error,
        baseline: describeRequirements(ctx.policy.postureBaseline),
      },
    });
    rerender(
      { text: `Device posture check failed: ${reasons.map((reason) => reason.message).join('; ')}`, kind: 'bad' },
      403,
    );
    return;
  }
  ctx.audit.record({
    event: 'device.check.pass',
    outcome: 'info',
    actor: { userId: user.id, deviceId: device.id, ip },
    detail: { stage: 'login', postureStatus: evaluation.status, score: evaluation.score },
  });

  ctx.loginLimiter.recordSuccess(rateKey);
  const created = ctx.sessions.create({
    userId: user.id,
    deviceId: device.id,
    certFingerprint256: device.certFingerprint256,
    sourceIp: ip,
    userAgent: truncate(req.headers['user-agent'] ?? '', 160),
  });
  ctx.audit.record({
    event: 'auth.login.success',
    outcome: 'allow',
    actor: { userId: user.id, deviceId: device.id, ip },
    sessionId: created.record.id,
  });

  const maxAge = ctx.policy.settings.sessionTtlMinutes * 60;
  redirect(res, nextPath === '/' ? `${CONTROL_PREFIX}/` : nextPath, {
    'set-cookie': [
      sessionCookie(created.token, maxAge),
      `${CSRF_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`,
    ],
  });
}

async function handleLogout(ctx: AppContext, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const form = await readForm(req, 8 * 1024);
  const auth = authenticate(ctx, req);
  if (auth) {
    if (!verifyCsrf(req, form.get('csrf'), auth.session)) {
      page(res, 403, 'Forbidden', '<main><div class="banner bad">Invalid request token.</div></main>');
      return;
    }
    ctx.sessions.revokeRecord(auth.session, 'logout');
    ctx.audit.record({
      event: 'auth.logout',
      outcome: 'info',
      actor: { userId: auth.user.id, deviceId: auth.session.deviceId, ip: clientIp(req) },
      sessionId: auth.session.id,
    });
  }
  redirect(res, `${CONTROL_PREFIX}/login`, { 'set-cookie': clearedSessionCookie() });
}

// ---------------------------------------------------------------------------
// Console
// ---------------------------------------------------------------------------

async function deviceRows(ctx: AppContext, devices: DeviceRecord[], now = Date.now()): Promise<DeviceRowView[]> {
  const liveSessions = ctx.sessions.live(now);
  // Refresh posture for the devices being displayed; otherwise a device that
  // has had no traffic would always render as "no report".
  await Promise.all(devices.map((device) => ctx.posture.get(device.id, now)));
  return devices.map((device) => {
    const snapshot = ctx.posture.peek(device.id);
    const facts = snapshot.record?.facts ?? null;
    const evaluation = ctx.policy.evaluateDevicePosture(device, facts, undefined, now);
    return {
      id: device.id,
      label: device.label,
      platform: device.platform,
      assignedTo: device.assignedTo,
      status: device.status,
      postureStatus: evaluation.status,
      score: facts ? evaluation.score : null,
      reasons: evaluation.reasons.map((reason) => reason.message),
      osVersion: facts?.osVersion ?? null,
      reportAgeSeconds: evaluation.reportAgeSeconds,
      certNotAfter: device.certNotAfter,
      fingerprint: device.certFingerprint256,
      sessions: liveSessions.filter((session) => session.deviceId === device.id).length,
    };
  });
}

function renderChainStatus(ctx: AppContext): string {
  const status = ctx.audit.verifyChain();
  return status.valid
    ? `<span class="tag ok">intact</span> <span class="muted-s">${status.entries} records</span>`
    : `<span class="tag bad">broken at #${status.brokenAt}</span> <span class="muted-s">${status.entries} records before break</span>`;
}

async function handleConsole(ctx: AppContext, req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const auth = authenticateWithCert(ctx, req);
  if (!auth) {
    redirect(res, `${CONTROL_PREFIX}/login?next=${encodeURIComponent(url.pathname)}`);
    return;
  }
  const { user, session } = auth;
  const isAdmin = user.role === 'admin';
  const [section = '', ...rest] = url.pathname.slice(CONTROL_PREFIX.length).split('/').filter(Boolean);

  if (section === '' || section === 'overview') {
    const allDevices = ctx.devices.list();
    const visibleDevices = isAdmin ? allDevices : allDevices.filter((device) => device.assignedTo === user.id);
    const sessions = ctx.sessions.views().filter((view) => isAdmin || view.userId === user.id);
    const enforcerStatus = ctx.enforcer.status;
    const settings = ctx.policy.settings;
    const liveVisible = ctx.sessions.live().filter((record) => isAdmin || record.userId === user.id).length;

    ctx.audit.record({
      event: 'admin.viewed',
      outcome: 'info',
      actor: { userId: user.id, deviceId: session.deviceId, ip: clientIp(req) },
      sessionId: session.id,
      detail: { page: 'overview' },
    });

    const body = `${pageHeader('Access console', `${user.displayName} (${user.id})`, session.csrfToken, isAdmin)}
<main>
  <section>
    <h2>Continuous authorization</h2>
    <div class="pad kv">
      <dt>Revocation SLA</dt><dd>${settings.revocationSlaSeconds}s · posture rechecked every ${settings.postureRecheckSeconds}s</dd>
      <dt>Last enforcement pass</dt><dd>${
        enforcerStatus.lastRunAt ? new Date(enforcerStatus.lastRunAt).toISOString() : 'pending'
      } · ${enforcerStatus.lastResult.checked} sessions checked · ${enforcerStatus.lastResult.revoked} revoked</dd>
      <dt>Your live sessions</dt><dd>${liveVisible}</dd>
      <dt>Audit chain</dt><dd>${renderChainStatus(ctx)}</dd>
      <dt>Posture service</dt><dd class="mono">${escapeHtml(ctx.config.postureServiceUrl)}</dd>
    </div>
  </section>
  <section>
    <h2>Devices</h2>
    ${renderDeviceTable(await deviceRows(ctx, visibleDevices), session.csrfToken, isAdmin)}
  </section>
  <section>
    <h2>Sessions</h2>
    ${renderSessions(sessions, session.csrfToken, isAdmin)}
  </section>
  <section>
    <h2>Applications &amp; effective policy</h2>
    ${renderApps(ctx.policy.apps, ctx.policy.postureBaseline, (appId) => {
      const app = ctx.policy.appById(appId);
      return app ? describeRequirements(ctx.policy.requirementsFor(app)) : '';
    })}
  </section>
  ${
    isAdmin
      ? `<section><h2>Recent decisions · <a href="${CONTROL_PREFIX}/audit">full log</a></h2>${renderAudit(ctx.audit.recent(30))}</section>`
      : ''
  }
</main>`;
    sendHtml(res, 200, layout('Access console', body));
    return;
  }

  if (section === 'audit') {
    if (!isAdmin) {
      page(res, 403, 'Forbidden', '<main><div class="banner bad">Administrator role required.</div></main>');
      return;
    }
    const event = url.searchParams.get('event') ?? undefined;
    const outcome = url.searchParams.get('outcome') ?? undefined;
    const entries = ctx.audit.recent(200, { event, outcome });
    const body = `${pageHeader('Audit log', `${user.displayName} (${user.id})`, session.csrfToken, true)}
<main>
  <section>
    <h2>Chain status</h2>
    <div class="pad">${renderChainStatus(ctx)}
      <p class="muted-s">Every access decision is appended with a hash of the previous record. Editing or
      deleting a record breaks the chain, and verification runs on every console view and health check.</p></div>
  </section>
  <section><h2>Events</h2>${renderAudit(entries)}</section>
</main>`;
    sendHtml(res, 200, layout('Audit log', body));
    return;
  }

  if (section === 'session' && rest[0]) {
    const target = ctx.sessions.all().find((record) => record.id === rest[0]);
    if (!target || (!isAdmin && target.userId !== user.id)) {
      page(res, 404, 'Not found', '<main><div class="banner bad">Session not found.</div></main>');
      return;
    }
    const body = `${pageHeader('Session detail', `${user.displayName} (${user.id})`, session.csrfToken, isAdmin)}
<main><section><h2>Session</h2><div class="pad kv">
  <dt>Id</dt><dd class="mono">${escapeHtml(target.id)}</dd>
  <dt>User</dt><dd>${escapeHtml(target.userId)}</dd>
  <dt>Device</dt><dd class="mono">${escapeHtml(target.deviceId)}</dd>
  <dt>Created</dt><dd>${new Date(target.createdAt).toISOString()}</dd>
  <dt>Expires</dt><dd>${new Date(target.expiresAt).toISOString()}</dd>
  <dt>State</dt><dd>${target.revokedAt === undefined ? 'live' : `revoked: ${escapeHtml(target.revokeReason ?? '')}`}</dd>
  <dt>Apps</dt><dd>${escapeHtml((target.apps ?? []).join(', ') || '—')}</dd>
  ${
    target.revokeReasons
      ? `<dt>Reasons</dt><dd>${target.revokeReasons.map((reason) => escapeHtml(reason.message)).join('<br>')}</dd>`
      : ''
  }
</div></section></main>`;
    sendHtml(res, 200, layout('Session', body));
    return;
  }

  page(res, 404, 'Not found', '<main><div class="banner bad">Page not found.</div></main>');
}

// ---------------------------------------------------------------------------
// Admin actions
// ---------------------------------------------------------------------------

async function handleAdminAction(ctx: AppContext, req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const auth = authenticateWithCert(ctx, req);
  if (!auth) {
    redirect(res, `${CONTROL_PREFIX}/login`);
    return;
  }
  if (auth.user.role !== 'admin') {
    ctx.audit.record({
      event: 'access.deny',
      outcome: 'deny',
      actor: { userId: auth.user.id, deviceId: auth.session.deviceId, ip: clientIp(req) },
      sessionId: auth.session.id,
      reasonCodes: ['rbac.admin_required'],
      message: 'non-admin attempted an admin action',
    });
    page(res, 403, 'Forbidden', '<main><div class="banner bad">Administrator role required.</div></main>');
    return;
  }
  const form = await readForm(req, 8 * 1024);
  if (!verifyCsrf(req, form.get('csrf'), auth.session)) {
    page(res, 400, 'Bad request', '<main><div class="banner bad">Invalid request token.</div></main>');
    return;
  }

  const parts = url.pathname.slice(CONTROL_PREFIX.length).split('/').filter(Boolean);
  // /_zta/admin/<resource>/<id>/<action>
  const [, resource, rawId, action] = parts;
  const id = rawId ? decodeURIComponent(rawId) : '';
  const ip = clientIp(req);

  if (resource === 'devices' && (action === 'revoke' || action === 'restore')) {
    const device = ctx.devices.get(id);
    if (!device) {
      page(res, 404, 'Not found', '<main><div class="banner bad">Unknown device.</div></main>');
      return;
    }
    if (action === 'revoke') {
      ctx.devices.setStatus(id, 'revoked', `revoked by ${auth.user.id}`);
      const revokedSessions = ctx.sessions.revokeForDevice(id, `device_revoked_by_${auth.user.id}`);
      ctx.posture.invalidate(id);
      ctx.audit.record({
        event: 'admin.device.revoked',
        outcome: 'info',
        actor: { userId: auth.user.id, deviceId: auth.session.deviceId, ip },
        sessionId: auth.session.id,
        detail: { targetDevice: id, sessionsRevoked: revokedSessions.length },
      });
    } else {
      ctx.devices.setStatus(id, 'active');
      ctx.audit.record({
        event: 'admin.device.restored',
        outcome: 'info',
        actor: { userId: auth.user.id, deviceId: auth.session.deviceId, ip },
        sessionId: auth.session.id,
        detail: { targetDevice: id },
      });
    }
    redirect(res, `${CONTROL_PREFIX}/`);
    return;
  }

  if (resource === 'sessions' && action === 'revoke') {
    const target = ctx.sessions.all().find((record) => record.id === id);
    if (!target) {
      page(res, 404, 'Not found', '<main><div class="banner bad">Unknown session.</div></main>');
      return;
    }
    ctx.sessions.revokeRecord(target, `revoked_by_${auth.user.id}`);
    ctx.audit.record({
      event: 'session.revoked',
      outcome: 'deny',
      actor: { userId: auth.user.id, deviceId: auth.session.deviceId, ip },
      sessionId: target.id,
      reasonCodes: ['admin.revoked'],
      detail: { targetUser: target.userId, targetDevice: target.deviceId },
    });
    redirect(res, `${CONTROL_PREFIX}/`);
    return;
  }

  page(res, 404, 'Not found', '<main><div class="banner bad">Unknown admin action.</div></main>');
}

// ---------------------------------------------------------------------------
// Proxy path
// ---------------------------------------------------------------------------

async function handleProxy(ctx: AppContext, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const auth = authenticateWithCert(ctx, req);
  if (!auth) {
    redirect(res, `${CONTROL_PREFIX}/login?next=${encodeURIComponent(req.url ?? '/')}`);
    return;
  }
  const { user, session } = auth;
  const device = ctx.devices.get(session.deviceId);
  if (!device) {
    ctx.sessions.revokeRecord(session, 'device_missing');
    redirect(res, `${CONTROL_PREFIX}/login`);
    return;
  }

  const url = new URL(req.url ?? '/', 'https://placeholder');
  // Policy matching and upstream forwarding must agree on the path. Reject
  // encoded separators/dot segments rather than let an upstream decode a path
  // the policy never saw.
  const resolved = resolveRequestPath(url.pathname);
  if (!resolved.ok) {
    ctx.audit.record({
      event: 'access.deny',
      outcome: 'deny',
      actor: { userId: user.id, deviceId: device.id, ip: clientIp(req) },
      sessionId: session.id,
      reasonCodes: ['policy.path_rejected'],
      message: `Rejected request path (${resolved.reason})`,
      detail: { path: truncate(req.url ?? '', 200) },
    });
    sendHtml(res, 400, layout('Bad request', '<main><div class="banner bad">Invalid request path.</div></main>'));
    return;
  }
  const path = resolved.path;
  const host = normalizeHost(req.headers.host);
  const app = ctx.policy.findApp(host, path, req.method ?? 'GET');
  if (!app) {
    ctx.audit.record({
      event: 'access.deny',
      outcome: 'deny',
      actor: { userId: user.id, deviceId: device.id, ip: clientIp(req) },
      sessionId: session.id,
      reasonCodes: ['policy.no_matching_app'],
      message: `No application policy matches host "${host}" path "${path}"`,
    });
    sendHtml(
      res,
      403,
      layout(
        'No matching application',
        '<main><div class="banner bad">No application is published at this address.</div></main>',
      ),
    );
    return;
  }

  const snapshot = await ctx.posture.get(device.id);
  const decision = ctx.policy.decide(
    app,
    user,
    device,
    snapshot.record?.facts ?? null,
    Date.now(),
    Math.floor((Date.now() - session.createdAt) / 1000),
  );
  const requestId = randomId('req', 8);
  // Remember which apps this session reached so the enforcer applies their
  // stricter posture requirements, but never record an app the caller was
  // refused — a denial must not widen what gets enforced later.
  if (decision.allow && !session.apps.includes(app.id)) session.apps.push(app.id);

  if (!decision.allow) {
    ctx.audit.record({
      event: 'access.deny',
      outcome: 'deny',
      actor: { userId: user.id, deviceId: device.id, ip: clientIp(req) },
      appId: app.id,
      sessionId: session.id,
      reasonCodes: decision.reasons.map((reason) => reason.code),
      message: decision.reasons.map((reason) => reason.message).join('; '),
      detail: {
        requestId,
        method: req.method,
        path: truncate(path, 200),
        postureStatus: decision.posture.status,
        score: decision.posture.score,
        fetchError: snapshot.error,
      },
    });
    sendHtml(
      res,
      403,
      layout(
        'Access denied',
        `<main>
  <section><h2>Access denied</h2><div class="pad">
    <p>Signed in as <strong>${escapeHtml(user.id)}</strong> on device <code>${escapeHtml(device.id)}</code>,
       but this request was blocked.</p>
    <ul class="reasons">${decision.reasons.map((reason) => `<li>${escapeHtml(reason.message)}</li>`).join('')}</ul>
    <p class="muted-s">Request <code>${escapeHtml(requestId)}</code> · app <code>${escapeHtml(app.id)}</code>
       · posture ${escapeHtml(decision.posture.status)} (${decision.posture.score}/100)</p>
    <p><a href="${CONTROL_PREFIX}/">Open the access console</a></p>
  </div></section>
</main>`,
      ),
    );
    return;
  }

  ctx.audit.record({
    event: 'access.allow',
    outcome: 'allow',
    actor: { userId: user.id, deviceId: device.id, ip: clientIp(req) },
    appId: app.id,
    sessionId: session.id,
    detail: {
      requestId,
      method: req.method,
      path: truncate(path, 200),
      postureStatus: decision.posture.status,
      score: decision.posture.score,
    },
  });

  await proxyRequest(req, res, {
    app,
    user: { id: user.id, displayName: user.displayName, groups: user.groups },
    device,
    posture: decision.posture,
    sessionId: session.id,
    requestId,
    path,
    log,
    timeoutMs: ctx.config.upstreamTimeoutMs,
  });
}

// ---------------------------------------------------------------------------
// Routing + server
// ---------------------------------------------------------------------------

export async function route(ctx: AppContext, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'https://placeholder');
  const path = url.pathname;

  res.setHeader('x-zta-proxy', '1');

  if (path === `${CONTROL_PREFIX}/healthz`) {
    const chain = ctx.audit.verifyChain();
    sendJson(res, 200, {
      ok: true,
      uptimeSeconds: Math.floor((Date.now() - ctx.startedAt) / 1000),
      liveSessions: ctx.sessions.live().length,
      devices: ctx.devices.list().length,
      auditChainValid: chain.valid,
      enforcer: ctx.enforcer.status,
    });
    return;
  }

  if (path === `${CONTROL_PREFIX}/login`) {
    if (req.method === 'GET') handleLoginGet(ctx, req, res);
    else if (req.method === 'POST') await handleLoginPost(ctx, req, res);
    else sendText(res, 405, 'Method not allowed\n');
    return;
  }

  if (path === `${CONTROL_PREFIX}/logout` && req.method === 'POST') {
    await handleLogout(ctx, req, res);
    return;
  }

  if (path.startsWith(`${CONTROL_PREFIX}/admin/`) && req.method === 'POST') {
    await handleAdminAction(ctx, req, res, url);
    return;
  }

  if (path === CONTROL_PREFIX || path.startsWith(`${CONTROL_PREFIX}/`)) {
    await handleConsole(ctx, req, res, url);
    return;
  }

  await handleProxy(ctx, req, res);
}

export interface RunningServer {
  server: ReturnType<typeof createHttpsServer>;
  port: number;
  close(): Promise<void>;
}

export function startServer(ctx: AppContext): Promise<RunningServer> {
  const tlsOptions = {
    ca: readFileSync(ctx.config.tlsCaFile),
    cert: readFileSync(ctx.config.tlsCertFile),
    key: readFileSync(ctx.config.tlsKeyFile),
    requestCert: true,
    // Identity is enforced per route, so certificate-less clients must still
    // reach the sign-in page (which explains why they are being refused).
    rejectUnauthorized: false,
    minVersion: 'TLSv1.2' as const,
  };

  const server = createHttpsServer(tlsOptions, (req, res) => {
    route(ctx, req, res).catch((error: unknown) => {
      if (error instanceof HttpError) {
        sendJson(res, error.status, { error: error.code, message: error.message });
        return;
      }
      log.error('unhandled request error', { error: (error as Error).message, url: truncate(req.url ?? '', 160) });
      if (!res.headersSent) sendText(res, 500, 'Internal server error\n');
      else res.destroy();
    });
  });

  server.on('tlsClientError', (error) => log.warn('tls client error', { error: error.message }));
  server.headersTimeout = 15_000;
  server.requestTimeout = 60_000;

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(ctx.config.port, ctx.config.host, () => {
      server.off('error', reject);
      const address = server.address();
      resolve({
        server,
        port: typeof address === 'object' && address ? address.port : ctx.config.port,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
            server.closeAllConnections?.();
          }),
      });
    });
  });
}


// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function main(): Promise<void> {
  const config = loadServiceConfig();
  const ctx = buildContext(config);
  ctx.enforcer.start();
  const running = await startServer(ctx);
  const chain = ctx.audit.verifyChain();
  log.info('access proxy listening', {
    url: `https://${config.host}:${running.port}`,
    policy: config.policyFile,
    postureService: config.postureServiceUrl,
    auditChainValid: chain.valid,
    revocationSlaSeconds: ctx.policy.settings.revocationSlaSeconds,
    recheckSeconds: ctx.policy.settings.postureRecheckSeconds,
  });
  if (!chain.valid) log.error('audit chain is broken', { brokenAt: chain.brokenAt });

  const shutdown = (signal: string) => {
    log.info('shutting down', { signal });
    ctx.enforcer.stop();
    void running.close().then(() => process.exit(0));
    setTimeout(() => process.exit(0), 3_000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
