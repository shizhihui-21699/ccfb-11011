/**
 * Continuous authorization.
 *
 * The revalidator periodically walks every active grant, re-runs the full
 * decision (device baseline + policy) against the freshest posture snapshot,
 * and revokes anything that no longer qualifies. When the failure is
 * device-wide, every session on that device is revoked too.
 *
 * Posture pushes from the posture service trigger an immediate pass for the
 * affected device instead of waiting for the next tick, which is what keeps
 * worst-case revocation latency well under the one-minute SLA.
 *
 * All revocation is fail-closed: an evaluator error revokes rather than
 * preserves access.
 */
import type { Config } from '../config.ts';
import type { AccessController } from './access.ts';
import type { SessionManager } from './sessions.ts';
import { PolicyFile } from '../policy/store.ts';
import type { AuditLog } from '../store/audit.ts';
import type { GrantStore, PostureStore, SessionStore } from '../store/repositories.ts';
import type { PostureSnapshotRecord } from '../store/types.ts';

export interface RevalidatorDeps {
  access: AccessController;
  sessions: SessionManager;
  policy: PolicyFile;
  audit: AuditLog;
  grants: GrantStore;
  sessionsStore: SessionStore;
  posture: PostureStore;
  config: Config;
  logger?: (event: string, detail: Record<string, unknown>) => void;
}

export interface RevalidationReport {
  trigger: string;
  startedAt: Date;
  finishedAt: Date;
  considered: number;
  revokedGrants: number;
  revokedSessions: number;
  allowed: number;
  errors: number;
  /** Highest observed single-evaluation latency, used by the SLA panel. */
  maxEvaluationMs: number;
  durationMs: number;
}

function emptyReport(trigger: string): RevalidationReport {
  const now = new Date();
  return {
    trigger,
    startedAt: now,
    finishedAt: now,
    considered: 0,
    revokedGrants: 0,
    revokedSessions: 0,
    allowed: 0,
    errors: 0,
    maxEvaluationMs: 0,
    durationMs: 0,
  };
}

export class Revalidator {
  private readonly deps: RevalidatorDeps;
  private timer: NodeJS.Timeout | null = null;
  private inFlight: Promise<RevalidationReport> | null = null;
  private lastReport: RevalidationReport | null = null;
  private readonly queuedDevices = new Set<string>();
  private stopped = false;

  constructor(deps: RevalidatorDeps) {
    this.deps = deps;
  }

  getLastReport(): RevalidationReport | null {
    return this.lastReport;
  }

  /** Starts periodic revalidation. Safe to call once. */
  start(): void {
    if (this.timer !== null) return;
    this.stopped = false;
    const interval = this.deps.config.thresholds.revalidateIntervalMs;
    this.timer = setInterval(() => {
      void this.runOnce('interval');
    }, interval);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
    // Queued passes must not touch the database after shutdown.
    this.stopped = true;
    this.queuedDevices.clear();
  }

  /**
   * Schedules an immediate pass for one device. Repeated calls while a pass is
   * running coalesce. Used by the posture push handler.
   */
  onPostureChanged(deviceId: string): void {
    if (this.stopped || this.queuedDevices.has(deviceId)) return;
    this.queuedDevices.add(deviceId);
    setImmediate(() => {
      this.queuedDevices.delete(deviceId);
      if (this.stopped) return;
      void this.runOnce('posture_push', deviceId).catch(() => {
        // runOnce handles per-grant errors; a rejection here means shutdown.
      });
    });
  }

  /** Runs one revalidation pass. Concurrent callers share the in-flight pass. */
  async runOnce(trigger: string, onlyDeviceId?: string): Promise<RevalidationReport> {
    if (this.stopped) return emptyReport(trigger);
    if (this.inFlight !== null) return this.inFlight;
    this.inFlight = this.execute(trigger, onlyDeviceId).finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  private async execute(trigger: string, onlyDeviceId?: string): Promise<RevalidationReport> {
    const startedAt = new Date();
    let revokedGrants = 0;
    let revokedSessions = 0;
    let allowed = 0;
    let errors = 0;
    let maxEvaluationMs = 0;

    const policy = this.deps.policy.get();
    if (policy.loadError !== null) {
      this.deps.logger?.('revalidate.policy_error', { error: policy.loadError });
    }

    const grants = this.deps.grants
      .listActive()
      .filter((grant) => onlyDeviceId === undefined || grant.deviceId === onlyDeviceId);

    const untrustedDevices = new Set<string>();

    for (const grant of grants) {
      try {
        const evaluatedAt = new Date();
        const session = this.deps.sessionsStore.findById(grant.sessionId);
        if (session === null || session.state !== 'active') {
          if (this.deps.sessions.revokeGrant(grant, 'parent session is no longer active', evaluatedAt)) {
            revokedGrants += 1;
          }
          continue;
        }

        const evaluationStart = performance.now();
        const decision = this.deps.access.revalidate(
          { userId: grant.userId, deviceId: grant.deviceId, appId: grant.appId },
          policy.current,
          evaluatedAt,
        );
        maxEvaluationMs = Math.max(maxEvaluationMs, performance.now() - evaluationStart);

        if (decision.allow) {
          this.deps.grants.touchEvaluation(grant.id, evaluatedAt.toISOString(), 'allow', decision.reason);
          allowed += 1;
          continue;
        }

        this.deps.audit.append({
          actorType: 'system',
          actorId: 'revalidator',
          action: 'access.revalidated',
          decision: 'deny',
          reason: decision.reason,
          appId: grant.appId,
          sessionId: grant.sessionId,
          deviceId: grant.deviceId,
          userId: grant.userId,
          detail: {
            trigger,
            code: decision.code,
            ruleId: decision.ruleId,
            requirements: decision.requirements,
          },
        });
        if (this.deps.sessions.revokeGrant(grant, decision.reason, evaluatedAt)) {
          revokedGrants += 1;
        }
        if (decision.deviceTrustFailure) untrustedDevices.add(grant.deviceId);
      } catch (error) {
        errors += 1;
        this.deps.logger?.('revalidate.error', {
          grantId: grant.id,
          error: error instanceof Error ? error.message : String(error),
        });
        // Fail closed: a broken evaluator must not preserve access.
        if (this.deps.sessions.revokeGrant(grant, 'authorization evaluation failed', new Date())) {
          revokedGrants += 1;
        }
        untrustedDevices.add(grant.deviceId);
      }
    }

    // Device-wide trust collapse revokes every session (and thus grant) on it.
    for (const deviceId of untrustedDevices) {
      const affected = this.deps.sessionsStore
        .listActive()
        .filter((session) => session.deviceId === deviceId);
      for (const session of affected) {
        const revoked = this.deps.sessions.revokeSession(
          session,
          'Device trust baseline failed; all sessions on this device were revoked.',
          new Date(),
          { type: 'system', id: 'revalidator' },
        );
        if (revoked) revokedSessions += 1;
      }
    }

    const finishedAt = new Date();
    const report: RevalidationReport = {
      trigger,
      startedAt,
      finishedAt,
      considered: grants.length,
      revokedGrants,
      revokedSessions,
      allowed,
      errors,
      maxEvaluationMs: Math.round(maxEvaluationMs * 100) / 100,
      durationMs: finishedAt.getTime() - startedAt.getTime(),
    };
    this.lastReport = report;
    if (revokedGrants > 0 || revokedSessions > 0 || errors > 0) {
      this.deps.logger?.('revalidate.completed', { ...report });
    }
    return report;
  }

  /**
   * Request-path check, so a revoked grant cannot be used between ticks.
   */
  checkGrantNow(grantId: string, now = new Date()): { ok: boolean; reason: string; code: string } {
    const grant = this.deps.grants.findById(grantId);
    if (grant === null) return { ok: false, reason: 'grant not found', code: 'grant_missing' };
    if (grant.state !== 'active') {
      return { ok: false, reason: grant.revokeReason ?? 'grant is not active', code: 'grant_inactive' };
    }
    if (new Date(grant.expiresAt).getTime() <= now.getTime()) {
      return { ok: false, reason: 'grant expired', code: 'grant_expired' };
    }
    const decision = this.deps.access.revalidate(
      { userId: grant.userId, deviceId: grant.deviceId, appId: grant.appId },
      this.deps.policy.get().current,
      now,
    );
    if (!decision.allow) return { ok: false, reason: decision.reason, code: decision.code };
    return { ok: true, reason: 'ok', code: 'allow' };
  }

  latestPosture(deviceId: string): PostureSnapshotRecord | null {
    return this.deps.posture.get(deviceId);
  }
}
