/**
 * Continuous authorization.
 *
 * Re-evaluates every live session on a fixed cadence, independent of traffic:
 * a device that degrades or is revoked loses its session within one recheck
 * interval, and policy validation keeps that interval below the revocation SLA.
 */
import type { DenialReason, SessionRecord } from './types.ts';
import type { PostureCache } from './posture/cache.ts';
import type { PolicyEngine } from './policy/engine.ts';
import type { DeviceStore } from './stores/deviceStore.ts';
import type { UserStore } from './stores/userStore.ts';
import type { SessionStore } from './auth/sessionStore.ts';
import type { AuditLog } from './audit.ts';
import type { Logger } from './log.ts';
import { dedupeReasons } from './util.ts';

export interface EnforcementOptions {
  intervalMs: number;
  policy: PolicyEngine;
  devices: DeviceStore;
  users: UserStore;
  posture: PostureCache;
  sessions: SessionStore;
  audit: AuditLog;
  log: Logger;
  /** Maximum sessions evaluated in parallel per pass. */
  concurrency?: number;
  now?: () => number;
}

export interface RecheckResult {
  checked: number;
  revoked: number;
}

export class SessionEnforcer {
  private readonly options: EnforcementOptions;
  private readonly now: () => number;
  private timer: ReturnType<typeof setInterval> | undefined;
  private running = false;
  private lastRunAt = 0;
  private lastResult: RecheckResult = { checked: 0, revoked: 0 };

  constructor(options: EnforcementOptions) {
    this.options = options;
    this.now = options.now ?? Date.now;
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.runOnce();
    }, this.options.intervalMs);
    this.timer.unref?.();
    this.options.log.info('session enforcement started', { intervalMs: this.options.intervalMs });
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  get status(): { lastRunAt: number; lastResult: RecheckResult; running: boolean } {
    return { lastRunAt: this.lastRunAt, lastResult: this.lastResult, running: this.running };
  }

  /** One evaluation pass over every live session. Exposed for deterministic tests. */
  async runOnce(): Promise<RecheckResult> {
    if (this.running) return this.lastResult;
    this.running = true;
    const now = this.now();
    let checked = 0;
    let revoked = 0;
    try {
      const live = this.options.sessions.live(now);
      // Bounded concurrency: posture lookups are network calls. Serially, a
      // slow posture service could push a pass past the revocation SLA on a
      // large fleet; unbounded, a pass could exhaust sockets.
      const results = await mapLimit(live, this.options.concurrency ?? 16, (session) =>
        this.evaluateSession(session, now),
      );
      checked = live.length;
      revoked = results.filter(Boolean).length;
      this.lastRunAt = now;
      this.lastResult = { checked, revoked };
      if (revoked > 0) this.options.log.warn('sessions revoked by enforcement pass', { checked, revoked });
      for (const expired of this.options.sessions.reapExpired(now)) {
        this.options.audit.record({
          event: 'session.expired',
          outcome: 'info',
          actor: { userId: expired.userId, deviceId: expired.deviceId },
          sessionId: expired.id,
          reasonCodes: [now >= expired.expiresAt ? 'session.ttl' : 'session.idle'],
        });
      }
      this.options.sessions.prune(now);
    } finally {
      this.running = false;
    }
    return this.lastResult;
  }

  /** Returns true when this pass revoked the session. */
  private async evaluateSession(session: SessionRecord, now: number): Promise<boolean> {
    const { devices, users, policy, posture, audit, log } = this.options;

    const device = devices.get(session.deviceId);
    if (!device) {
      return this.revoke(session, [{ code: 'device.unknown', message: `Device ${session.deviceId} is no longer registered` }], now);
    }
    if (device.status !== 'active') {
      return this.revoke(session, [{ code: 'device.revoked', message: `Device ${device.id} was revoked` }], now);
    }
    if (session.certFingerprint256 !== device.certFingerprint256) {
      return this.revoke(
        session,
        [{ code: 'device.cert_changed', message: 'The device certificate no longer matches the enrolled certificate' }],
        now,
      );
    }
    const user = users.get(session.userId);
    if (!user) {
      return this.revoke(session, [{ code: 'user.unknown', message: `User ${session.userId} no longer exists` }], now);
    }

    const snapshot = await posture.get(device.id, now);
    const facts = snapshot.record?.facts ?? null;

    // The device baseline always applies. Per-app posture requirements apply
    // only to apps this session has actually reached: a session must not be
    // torn down because of a policy for an app the user never used (or is not
    // authorized for). Session-age limits stay a per-request control and are
    // not evaluated here.
    const failures: (DenialReason & { appId?: string })[] = [];
    let worst = policy.evaluateDevicePosture(device, facts, undefined, now);
    failures.push(...policy.deviceChecks(device));
    for (const reason of worst.reasons) failures.push(reason);

    for (const appId of session.apps) {
      const app = policy.appById(appId);
      if (!app) continue;
      const postureOnly = policy.evaluateDevicePosture(device, facts, app, now);
      if (postureOnly.score < worst.score) worst = postureOnly;
      for (const reason of postureOnly.reasons) failures.push({ ...reason, appId: app.id });
    }
    if (failures.length > 0) {
      const unique = dedupeReasons(failures);
      const codes = unique.map((failure) => failure.code);
      const revoked = this.revoke(session, unique, now);
      // Latency measured from when the posture service recorded the change,
      // which is the earliest point this proxy could have known.
      const postureChangedAt = snapshot.record ? Date.parse(snapshot.record.updatedAt) : Number.NaN;
      audit.record({
        event: 'posture.recheck',
        outcome: 'deny',
        actor: { userId: session.userId, deviceId: session.deviceId },
        sessionId: session.id,
        reasonCodes: codes,
        detail: {
          postureStatus: worst.status,
          score: worst.score,
          fetchError: snapshot.error,
          reportAgeSeconds: worst.reportAgeSeconds,
          revocationLatencySeconds: Number.isFinite(postureChangedAt)
            ? Math.max(0, Math.round((now - postureChangedAt) / 1000))
            : null,
        },
      });
      log.info('session revoked on recheck', { sessionId: session.id, deviceId: session.deviceId, codes });
      return revoked;
    }
    return false;
  }

  private revoke(session: SessionRecord, reasons: DenialReason[], now: number): boolean {
    const { sessions, audit } = this.options;
    if (session.revokedAt !== undefined) return false;
    sessions.revokeRecord(session, reasons.map((item) => item.code).join(','), reasons, now);
    audit.record({
      event: 'session.revoked',
      outcome: 'deny',
      actor: { userId: session.userId, deviceId: session.deviceId },
      sessionId: session.id,
      reasonCodes: reasons.map((item) => item.code),
      message: reasons.map((item) => item.message).join('; '),
      detail: {
        sessionAgeSeconds: Math.floor((now - session.createdAt) / 1000),
        revocationSlaSeconds: this.options.policy.settings.revocationSlaSeconds,
        recheckIntervalSeconds: this.options.intervalMs / 1000,
      },
    });
    return true;
  }
}

/** Run `worker` over `items` with at most `limit` in flight, preserving order. */
async function mapLimit<T, R>(items: T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(Math.max(1, limit), items.length || 1) }, async () => {
    for (;;) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await worker(items[index]);
    }
  });
  await Promise.all(runners);
  return results;
}
