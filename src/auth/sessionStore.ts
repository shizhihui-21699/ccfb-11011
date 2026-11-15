/**
 * Server-side sessions. Only a hash of the cookie value is stored, so a
 * memory dump or log leak does not yield usable session tokens.
 */
import type { SessionRecord, SessionView } from '../types.ts';
import { randomToken, sha256Hex } from '../util.ts';

export interface SessionTtl {
  ttlMs: number;
  idleMs: number;
}

export interface CreateSessionInput {
  userId: string;
  deviceId: string;
  certFingerprint256: string;
  sourceIp?: string;
  userAgent?: string;
}

export class SessionStore {
  private readonly byHash = new Map<string, SessionRecord>();
  private readonly ttl: SessionTtl;
  private readonly maxSessions: number;
  onRevoke?: (record: SessionRecord) => void;

  constructor(ttl: SessionTtl, maxSessions = 10_000) {
    this.ttl = ttl;
    this.maxSessions = maxSessions;
  }

  create(input: CreateSessionInput, now = Date.now()): { token: string; record: SessionRecord } {
    const token = randomToken(32);
    const record: SessionRecord = {
      id: `sess_${randomToken(9)}`,
      userId: input.userId,
      deviceId: input.deviceId,
      certFingerprint256: input.certFingerprint256,
      csrfToken: randomToken(24),
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + this.ttl.ttlMs,
      sourceIp: input.sourceIp,
      userAgent: input.userAgent,
      apps: [],
    };
    this.byHash.set(sha256Hex(token), record);
    this.prune(now);
    return { token, record };
  }

  /**
   * Resolve a cookie token. Returns the live record, refreshing the idle timer,
   * or a reason why the session is no longer valid.
   */
  resolve(
    token: string,
    now = Date.now(),
  ): { ok: true; record: SessionRecord } | { ok: false; reason: 'unknown' | 'expired' | 'idle' | 'revoked' } {
    const record = this.byHash.get(sha256Hex(token));
    if (!record) return { ok: false, reason: 'unknown' };
    if (record.revokedAt !== undefined) return { ok: false, reason: 'revoked' };
    if (now >= record.expiresAt) return { ok: false, reason: 'expired' };
    if (now - record.lastSeenAt >= this.ttl.idleMs) return { ok: false, reason: 'idle' };
    record.lastSeenAt = now;
    return { ok: true, record };
  }

  /** Non-mutating lookup used by the re-evaluation loop. */
  peek(token: string): SessionRecord | undefined {
    return this.byHash.get(sha256Hex(token));
  }

  revoke(sessionId: string, reason: string, reasons?: SessionRecord['revokeReasons'], now = Date.now()): SessionRecord | undefined {
    for (const record of this.byHash.values()) {
      if (record.id !== sessionId) continue;
      this.revokeRecord(record, reason, reasons, now);
      return record;
    }
    return undefined;
  }

  revokeRecord(record: SessionRecord, reason: string, reasons?: SessionRecord['revokeReasons'], now = Date.now()): void {
    if (record.revokedAt !== undefined) return;
    record.revokedAt = now;
    record.revokeReason = reason;
    record.revokeReasons = reasons;
    this.onRevoke?.(record);
  }

  revokeForDevice(deviceId: string, reason: string, now = Date.now()): SessionRecord[] {
    const revoked: SessionRecord[] = [];
    for (const record of this.byHash.values()) {
      if (record.deviceId !== deviceId || record.revokedAt !== undefined) continue;
      this.revokeRecord(record, reason, undefined, now);
      revoked.push(record);
    }
    return revoked;
  }

  live(now = Date.now()): SessionRecord[] {
    return [...this.byHash.values()].filter(
      (record) => record.revokedAt === undefined && now < record.expiresAt && now - record.lastSeenAt < this.ttl.idleMs,
    );
  }

  all(): SessionRecord[] {
    return [...this.byHash.values()];
  }

  views(now = Date.now()): SessionView[] {
    return [...this.byHash.values()]
      .map((record) => ({
        ...record,
        ageSeconds: Math.floor((now - record.createdAt) / 1000),
        idleSeconds: Math.floor((now - record.lastSeenAt) / 1000),
      }))
      .sort((a, b) => b.createdAt - a.createdAt);
  }

  size(): number {
    return this.byHash.size;
  }

  /** Drop records that are expired, revoked, or idle past any recovery. */
  prune(now = Date.now()): void {
    if (this.byHash.size <= this.maxSessions) return;
    for (const [hash, record] of this.byHash) {
      if (record.revokedAt !== undefined || now >= record.expiresAt) this.byHash.delete(hash);
    }
  }

  /**
   * Collect and forget sessions that reached their hard or idle limit.
   * Returned so the caller can audit the end of each session exactly once.
   */
  reapExpired(now = Date.now()): SessionRecord[] {
    const expired: SessionRecord[] = [];
    for (const [hash, record] of this.byHash) {
      if (record.revokedAt !== undefined) continue;
      const reason = now >= record.expiresAt ? 'expired' : now - record.lastSeenAt >= this.ttl.idleMs ? 'idle' : null;
      if (!reason) continue;
      this.byHash.delete(hash);
      expired.push(record);
    }
    return expired;
  }
}
