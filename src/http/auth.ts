/**
 * Authentication: password login bound to the device certificate, plus
 * logout and the session cookie.
 *
 * Security properties:
 *   - The login form is only reachable on a TLS connection that presented a
 *     valid device certificate; the device id used for the grant comes from
 *     that certificate.
 *   - The session cookie is AES-GCM sealed with the device id and cert
 *     fingerprint as AAD, so copying it to another device's connection does
 *     not open.
 *   - Credentials are verified with scrypt; failures are rate-limited per
 *     (username, device) using the persisted failure log.
 *   - Every attempt is audited, including the device id and source IP.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Runtime } from '../core/runtime.ts';
import type { ClientIdentity } from '../pki/trust.ts';
import { verifyPassword } from '../crypto/password.ts';
import { openSealed, seal } from '../crypto/seal.ts';
import { randomToken } from '../util/ids.ts';
import {
  clientIp,
  clearCookie,
  parseCookies,
  parseForm,
  readBody,
  redirect,
  sendHtml,
  sendText,
} from './respond.ts';
import { loginPage } from './views/login.ts';
import type { SessionRecord } from '../store/types.ts';

const SESSION_COOKIE = 'zt_session';
const NONCE_COOKIE = 'zt_login_nonce';
const SESSION_PURPOSE = 'session-cookie';
const MAX_FAILURES = 6;
const FAILURE_WINDOW_MINUTES = 15;

export interface AuthenticatedContext {
  session: SessionRecord;
  device: ClientIdentity;
  ip: string;
}

/** Extracts the sealed session token from a request. */
export function sessionTokenFrom(req: IncomingMessage): string | null {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies.get(SESSION_COOKIE);
  return token === undefined || token === '' ? null : token;
}

export function sealSessionCookie(
  runtime: Runtime,
  sessionId: string,
  device: ClientIdentity,
  now = Date.now(),
): { header: string; value: string } {
  const aad = `${device.deviceId}:${device.fingerprint256}`;
  const sealed = seal(
    { sid: sessionId, ttl: runtime.config.sessionTtlSeconds },
    runtime.config.sessionSecret,
    SESSION_PURPOSE,
    runtime.config.sessionTtlSeconds,
    aad,
    now,
  );
  return {
    value: sealed.value,
    header: `${SESSION_COOKIE}=${encodeURIComponent(sealed.value)}; Path=/; Max-Age=${runtime.config.sessionTtlSeconds}; HttpOnly; Secure; SameSite=Lax`,
  };
}

/**
 * Resolves the session from the cookie. Returns null (and audits) when the
 * cookie is invalid, sealed for another device, or refers to a dead session.
 */
export function resolveSession(
  runtime: Runtime,
  req: IncomingMessage,
  device: ClientIdentity,
  ip: string,
): SessionRecord | null {
  const token = sessionTokenFrom(req);
  if (token === null) return null;
  const aad = `${device.deviceId}:${device.fingerprint256}`;
  const payload = openSealed(
    decodeURIComponent(token),
    runtime.config.sessionSecret,
    SESSION_PURPOSE,
    aad,
  );
  if (payload === null || typeof payload.sid !== 'string') {
    runtime.audit.append({
      actorType: 'device',
      actorId: device.deviceId,
      action: 'session.token_invalid',
      decision: 'deny',
      reason: 'Session cookie failed to open; it may have been copied from another device or tampered with.',
      deviceId: device.deviceId,
      ip,
    });
    return null;
  }
  return runtime.sessionManager.resolve(
    payload.sid,
    { deviceId: device.deviceId, fingerprint256: device.fingerprint256 },
    new Date(),
    ip,
  );
}

export function logout(runtime: Runtime, session: SessionRecord, ip: string, deviceId: string): void {
  runtime.sessionManager.revokeSession(session, 'user signed out', new Date(), {
    type: 'user',
    id: session.userId,
  });
  void ip;
  void deviceId;
}

export interface LoginResult {
  ok: boolean;
  message: string;
  /** Set on success. */
  sessionId?: string;
  userHint?: string | null;
}

/**
 * Checks the submitted credentials for a device. Rate limited; records every
 * outcome in the audit log and the failure table.
 */
export async function attemptLogin(
  runtime: Runtime,
  input: { username: string; password: string; nonce: string; formNonce: string },
  device: ClientIdentity,
  ip: string,
  userAgent: string,
  now = new Date(),
): Promise<LoginResult> {
  const username = input.username.trim().toLowerCase();
  if (input.formNonce !== input.nonce) {
    runtime.audit.append({
      actorType: 'device',
      actorId: device.deviceId,
      action: 'auth.login',
      decision: 'deny',
      reason: 'CSRF nonce mismatch on login form.',
      deviceId: device.deviceId,
      ip,
      detail: { username },
    });
    return { ok: false, message: 'The sign-in form expired. Reload the page and try again.' };
  }
  if (isRateLimited(runtime, username, device.deviceId, now)) {
    runtime.audit.append({
      actorType: 'device',
      actorId: device.deviceId,
      action: 'auth.login',
      decision: 'deny',
      reason: 'Too many failed sign-in attempts; temporarily blocked.',
      deviceId: device.deviceId,
      ip,
      detail: { username },
    });
    return { ok: false, message: 'Too many failed attempts. Wait a few minutes and try again.' };
  }

  const record = runtime.users.findByUsername(username);
  const passwordOk =
    record !== null && !record.disabled && (await verifyPassword(input.password, record.passwordHash));

  if (record === null || !passwordOk) {
    recordFailure(runtime, username, device.deviceId, ip, now);
    runtime.audit.append({
      actorType: 'device',
      actorId: device.deviceId,
      action: 'auth.login',
      decision: 'deny',
      reason: record === null ? 'Unknown username.' : record.disabled ? 'Account disabled.' : 'Incorrect password.',
      deviceId: device.deviceId,
      userId: record?.id ?? null,
      ip,
      detail: { username },
    });
    return { ok: false, message: 'Invalid username or password.' };
  }

  const deviceRecord = runtime.devices.findByFingerprint(device.fingerprint256);
  if (deviceRecord === null) {
    runtime.audit.append({
      actorType: 'device',
      actorId: device.deviceId,
      action: 'auth.login',
      decision: 'deny',
      reason: 'Certificate was signed by the device CA but is not registered (fingerprint unknown).',
      deviceId: device.deviceId,
      userId: record.id,
      ip,
      detail: { username, fingerprint: device.fingerprint256.slice(0, 16) },
    });
    return { ok: false, message: 'This device is not enrolled. Contact IT to enroll it.' };
  }
  if (deviceRecord.status !== 'enrolled') {
    runtime.audit.append({
      actorType: 'device',
      actorId: deviceRecord.id,
      action: 'auth.login',
      decision: 'deny',
      reason: deviceRecord.revokedReason ?? 'Device is revoked.',
      deviceId: deviceRecord.id,
      userId: record.id,
      ip,
      detail: { username },
    });
    return { ok: false, message: 'This device has been revoked. Contact IT.' };
  }
  if (deviceRecord.ownerUserId !== null && deviceRecord.ownerUserId !== record.id) {
    runtime.audit.append({
      actorType: 'device',
      actorId: deviceRecord.id,
      action: 'auth.login',
      decision: 'deny',
      reason: 'Certificate belongs to a different user.',
      deviceId: deviceRecord.id,
      userId: record.id,
      ip,
      detail: { username, ownerUserId: deviceRecord.ownerUserId },
    });
    return { ok: false, message: 'This device is enrolled to a different user.' };
  }

  runtime.devices.touch(deviceRecord.id, now.toISOString());
  const session = runtime.sessionManager.createSession(
    {
      userId: record.id,
      deviceId: deviceRecord.id,
      certFingerprint256: device.fingerprint256,
      ip,
      userAgent,
    },
    now,
  );
  runtime.audit.append({
    actorType: 'user',
    actorId: record.id,
    action: 'auth.login',
    decision: 'allow',
    reason: 'Password and device certificate both valid.',
    sessionId: session.id,
    deviceId: deviceRecord.id,
    userId: record.id,
    ip,
    detail: { username, fingerprint: device.fingerprint256.slice(0, 16) },
  });
  return { ok: true, message: 'Signed in.', sessionId: session.id, userHint: device.userHint };
}

function isRateLimited(runtime: Runtime, username: string, deviceId: string, now: Date): boolean {
  const since = new Date(now.getTime() - FAILURE_WINDOW_MINUTES * 60 * 1000).toISOString();
  const row = runtime.db
    .prepare(
      `SELECT COUNT(*) AS n FROM auth_failures WHERE username = ? AND device_id = ? AND ts >= ?`,
    )
    .get(username, deviceId, since) as { n?: number } | undefined;
  return Number(row?.n ?? 0) >= MAX_FAILURES;
}

function recordFailure(runtime: Runtime, username: string, deviceId: string, ip: string, now: Date): void {
  runtime.db
    .prepare('INSERT INTO auth_failures (ts, username, device_id, ip, reason) VALUES (?, ?, ?, ?, ?)')
    .run(now.toISOString(), username, deviceId, ip, 'invalid credentials');
}

/** Handles GET /login and POST /login. */
export async function handleLogin(
  runtime: Runtime,
  req: IncomingMessage,
  res: ServerResponse,
  device: ClientIdentity,
): Promise<void> {
  const ip = clientIp(req, runtime.config.trustProxy);
  const url = new URL(req.url ?? '/login', runtime.config.publicOrigin);
  const next = sanitizeNext(url.searchParams.get('next'));

  if (req.method === 'GET') {
    const nonce = randomToken(16);
    const nonceHeader = `${NONCE_COOKIE}=${encodeURIComponent(nonce)}; Path=/login; Max-Age=600; HttpOnly; Secure; SameSite=Lax`;
    const token = sessionTokenFrom(req);
    if (token !== null) {
      const session = resolveSession(runtime, req, device, ip);
      if (session !== null) {
        redirect(res, next ?? '/console');
        return;
      }
    }
    res.setHeader('set-cookie', nonceHeader);
    sendHtml(res, 200, loginPage({ nonce, next, device, error: url.searchParams.get('error') ?? undefined }));
    return;
  }

  if (req.method === 'POST') {
    const body = await readBody(req);
    const form = parseForm(body);
    const nonce = form.get('nonce') ?? '';
    const cookieNonce = parseCookies(req.headers.cookie).get(NONCE_COOKIE) ?? '';
    const result = await attemptLogin(
      runtime,
      {
        username: form.get('username') ?? '',
        password: form.get('password') ?? '',
        nonce: cookieNonce,
        formNonce: nonce,
      },
      device,
      ip,
      String(req.headers['user-agent'] ?? ''),
    );
    if (!result.ok || result.sessionId === undefined) {
      const freshNonce = randomToken(16);
      res.setHeader(
        'set-cookie',
        `${NONCE_COOKIE}=${encodeURIComponent(freshNonce)}; Path=/login; Max-Age=600; HttpOnly; Secure; SameSite=Lax`,
      );
      sendHtml(res, 401, loginPage({ nonce: freshNonce, next, device, error: result.message }));
      return;
    }
    const cookie = sealSessionCookie(runtime, result.sessionId, device, Date.now());
    res.setHeader('set-cookie', [cookie.header, clearCookie(NONCE_COOKIE, '/login')]);
    redirect(res, next ?? '/console');
    return;
  }

  sendText(res, 405, 'method not allowed');
}

/** Handles POST /logout. */
export async function handleLogout(
  runtime: Runtime,
  req: IncomingMessage,
  res: ServerResponse,
  session: SessionRecord,
): Promise<void> {
  const ip = clientIp(req, runtime.config.trustProxy);
  runtime.sessionManager.revokeSession(session, 'user signed out', new Date(), {
    type: 'user',
    id: session.userId,
  });
  runtime.audit.append({
    actorType: 'user',
    actorId: session.userId,
    action: 'auth.logout',
    decision: 'info',
    reason: 'User signed out.',
    sessionId: session.id,
    deviceId: session.deviceId,
    userId: session.userId,
    ip,
  });
  res.setHeader('set-cookie', clearCookie(SESSION_COOKIE));
  redirect(res, '/login');
}

/** Prevents open redirects: only same-site absolute paths are accepted. */
export function sanitizeNext(value: string | null): string | null {
  if (value === null) return null;
  if (!value.startsWith('/') || value.startsWith('//')) return null;
  if (value.includes('\\') || value.includes('\n') || value.includes('\r')) return null;
  return value;
}

export { SESSION_COOKIE, SESSION_PURPOSE };
