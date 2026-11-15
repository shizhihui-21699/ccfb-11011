/**
 * Session and grant lifecycle.
 *
 * Sessions are created at login, grants at per-application authorization.
 * Every state transition writes an audit record and is expressed so that the
 * revalidator can call it repeatedly without double-revoking.
 */
import type { Config } from '../config.ts';
import type { AuditLog } from '../store/audit.ts';
import type { DeviceStore, GrantStore, SessionStore, UserStore } from '../store/repositories.ts';
import type { GrantRecord, SessionRecord } from '../store/types.ts';
import { newId } from '../util/ids.ts';

export interface SessionContext {
  userId: string;
  deviceId: string;
  certFingerprint256: string;
  ip: string;
  userAgent: string;
}

export interface SessionManagerDeps {
  users: UserStore;
  devices: DeviceStore;
  sessions: SessionStore;
  grants: GrantStore;
  audit: AuditLog;
  config: Config;
}

export class SessionManager {
  private readonly deps: SessionManagerDeps;

  constructor(deps: SessionManagerDeps) {
    this.deps = deps;
  }

  createSession(context: SessionContext, now = new Date()): SessionRecord {
    const record: SessionRecord = {
      id: newId('sess'),
      userId: context.userId,
      deviceId: context.deviceId,
      certFingerprint256: context.certFingerprint256,
      ip: context.ip,
      userAgent: context.userAgent,
      state: 'active',
      createdAt: now.toISOString(),
      lastSeenAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + this.deps.config.sessionTtlSeconds * 1000).toISOString(),
      revokedAt: null,
      revokeReason: null,
    };
    this.deps.sessions.insert(record);
    this.deps.audit.append({
      actorType: 'user',
      actorId: context.userId,
      action: 'session.created',
      decision: 'allow',
      reason: 'User authenticated with a device certificate.',
      sessionId: record.id,
      deviceId: context.deviceId,
      userId: context.userId,
      ip: context.ip,
      detail: { certFingerprint256: context.certFingerprint256 },
    });
    return record;
  }

  /**
   * Returns the live session for a cookie value, or null when it is not
   * active, has expired, or does not match the connection's device
   * certificate. A mismatch is treated as an attack signal and audited.
   */
  resolve(
    sessionId: string,
    device: { deviceId: string; fingerprint256: string },
    now = new Date(),
    ip: string | null = null,
  ): SessionRecord | null {
    const session = this.deps.sessions.findById(sessionId);
    if (session === null) return null;
    if (session.state !== 'active') return null;
    if (new Date(session.expiresAt).getTime() <= now.getTime()) {
      this.expireSession(session, now);
      return null;
    }
    if (session.deviceId !== device.deviceId) {
      this.deps.audit.append({
        actorType: 'device',
        actorId: device.deviceId,
        action: 'session.device_mismatch',
        decision: 'deny',
        reason: 'Session cookie was presented from a different device certificate.',
        sessionId: session.id,
        deviceId: device.deviceId,
        userId: session.userId,
        ip,
        detail: { sessionDeviceId: session.deviceId, presentedDeviceId: device.deviceId },
      });
      return null;
    }
    if (session.certFingerprint256 !== device.fingerprint256) {
      this.deps.audit.append({
        actorType: 'device',
        actorId: device.deviceId,
        action: 'session.cert_mismatch',
        decision: 'deny',
        reason: 'Session certificate fingerprint no longer matches; device certificate was reissued.',
        sessionId: session.id,
        deviceId: device.deviceId,
        userId: session.userId,
        ip,
        detail: { expected: session.certFingerprint256.slice(0, 16), presented: device.fingerprint256.slice(0, 16) },
      });
      return null;
    }
    this.deps.sessions.touch(session.id, now.toISOString());
    return session;
  }

  createGrant(
    session: SessionRecord,
    appId: string,
    decision: { code: string; reason: string; ruleId: string | null },
    now = new Date(),
  ): GrantRecord {
    const existing = this.deps.grants.findBySessionApp(session.id, appId);
    if (existing !== null) {
      this.deps.grants.touchEvaluation(existing.id, now.toISOString(), 'allow', decision.reason);
      return existing;
    }
    const grant: GrantRecord = {
      id: newId('grant'),
      sessionId: session.id,
      userId: session.userId,
      deviceId: session.deviceId,
      appId,
      state: 'active',
      createdAt: now.toISOString(),
      lastEvaluatedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + this.deps.config.grantTtlSeconds * 1000).toISOString(),
      revokedAt: null,
      revokeReason: null,
      lastDecision: 'allow',
      lastReason: decision.reason,
    };
    this.deps.grants.insert(grant);
    this.deps.audit.append({
      actorType: 'user',
      actorId: session.userId,
      action: 'grant.created',
      decision: 'allow',
      reason: decision.reason,
      appId,
      sessionId: session.id,
      deviceId: session.deviceId,
      userId: session.userId,
      detail: { grantId: grant.id, ruleId: decision.ruleId, code: decision.code },
    });
    return grant;
  }

  /** Active grant for this session/app, or null (expiring it if overdue). */
  resolveGrant(session: SessionRecord, appId: string, now = new Date()): GrantRecord | null {
    const grant = this.deps.grants.findBySessionApp(session.id, appId);
    if (grant === null) return null;
    if (new Date(grant.expiresAt).getTime() <= now.getTime()) {
      this.deps.grants.revoke(grant.id, now.toISOString(), 'grant expired');
      return null;
    }
    return grant;
  }

  revokeGrant(
    grant: GrantRecord,
    reason: string,
    now = new Date(),
    actor: { type: 'system' | 'admin' | 'user'; id: string } = { type: 'system', id: 'revalidator' },
  ): boolean {
    if (grant.state !== 'active') return false;
    this.deps.grants.revoke(grant.id, now.toISOString(), reason);
    this.deps.audit.append({
      actorType: actor.type,
      actorId: actor.id,
      action: 'grant.revoked',
      decision: 'deny',
      reason,
      appId: grant.appId,
      sessionId: grant.sessionId,
      deviceId: grant.deviceId,
      userId: grant.userId,
      detail: { grantId: grant.id },
    });
    return true;
  }

  revokeSession(session: SessionRecord, reason: string, now = new Date(), actor: { type: 'system' | 'admin' | 'user'; id: string } = { type: 'system', id: 'revalidator' }): boolean {
    if (session.state !== 'active') return false;
    this.deps.sessions.setState(session.id, 'revoked', now.toISOString(), reason);
    const revokedGrants = this.deps.grants.revokeForSession(session.id, now.toISOString(), reason);
    this.deps.audit.append({
      actorType: actor.type,
      actorId: actor.id,
      action: 'session.revoked',
      decision: 'deny',
      reason,
      sessionId: session.id,
      deviceId: session.deviceId,
      userId: session.userId,
      detail: { revokedGrants },
    });
    return true;
  }

  private expireSession(session: SessionRecord, now = new Date()): void {
    if (session.state !== 'active') return;
    this.deps.sessions.setState(session.id, 'expired', null, 'session TTL reached');
    const revoked = this.deps.grants.revokeForSession(session.id, now.toISOString(), 'session expired');
    this.deps.audit.append({
      actorType: 'system',
      actorId: 'session-expiry',
      action: 'session.expired',
      decision: 'info',
      reason: 'Session lifetime ended.',
      sessionId: session.id,
      deviceId: session.deviceId,
      userId: session.userId,
      detail: { revokedGrants: revoked },
    });
  }
}
