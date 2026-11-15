/**
 * Policy engine: maps (user, device, request) to an application and evaluates
 * the full set of checks. Pure functions here make every decision reproducible
 * from its audit record.
 */
import type {
  AccessDecision,
  AppPolicy,
  AuthenticatedUser,
  DenialReason,
  DeviceRecord,
  PolicyFile,
  PostureEvaluation,
  PostureFacts,
  PostureRequirements,
} from '../types.ts';
import { matchesHostPattern, matchesPathPrefix } from '../util.ts';
import { mergePostureRequirements } from '../config.ts';
import { evaluatePosture } from '../posture/evaluate.ts';

export class PolicyEngine {
  private readonly policy: PolicyFile;

  constructor(policy: PolicyFile) {
    this.policy = policy;
  }

  get settings() {
    return this.policy.settings;
  }

  get apps(): readonly AppPolicy[] {
    return this.policy.apps;
  }

  get postureBaseline(): PostureRequirements {
    return this.policy.postureBaseline;
  }

  appById(appId: string): AppPolicy | undefined {
    return this.policy.apps.find((app) => app.id === appId);
  }

  /**
   * Pick the most specific application for a host + path.
   *
   * Specificity is decided by host + path alone, then the method is checked
   * against the winner. Checking the method first would let a more specific
   * path with a method restriction be bypassed by a broader parent path that
   * accepts every method.
   */
  findApp(host: string, pathname: string, method = 'GET'): AppPolicy | undefined {
    const normalizedHost = host.toLowerCase();
    let best: { app: AppPolicy; prefixLength: number; order: number } | undefined;
    this.policy.apps.forEach((app, order) => {
      const hostMatches = app.hosts.some(
        (pattern) => pattern === '*' || matchesHostPattern(normalizedHost, pattern),
      );
      if (!hostMatches) return;
      for (const prefix of app.paths ?? ['/']) {
        if (!matchesPathPrefix(pathname, prefix)) continue;
        const length = prefix === '/' ? 0 : prefix.replace(/\/$/, '').length;
        const better = !best || length > best.prefixLength || (length === best.prefixLength && order < best.order);
        if (better) best = { app, prefixLength: length, order };
      }
    });
    if (!best) return undefined;
    if (best.app.methods && !best.app.methods.includes(method.toUpperCase())) return undefined;
    return best.app;
  }

  /** Baseline merged with the app's own requirement; app values win per field. */
  requirementsFor(app: AppPolicy): PostureRequirements {
    return mergePostureRequirements(this.policy.postureBaseline, app.require?.posture);
  }

  /** Authorization + device-state checks, independent of posture data. */
  staticChecks(
    app: AppPolicy,
    user: AuthenticatedUser,
    device: DeviceRecord,
    sessionAgeSeconds?: number,
  ): DenialReason[] {
    const checks: DenialReason[] = [];
    const userAllowed = app.allow.users?.includes(user.id) ?? false;
    const groupAllowed = app.allow.groups?.some((group) => user.groups.includes(group)) ?? false;
    if (!userAllowed && !groupAllowed) {
      checks.push({ code: 'rbac.user_not_allowed', message: `User ${user.id} is not authorized for app ${app.id}` });
    }
    if (device.status !== 'active') {
      checks.push({ code: 'device.revoked', message: `Device ${device.id} is revoked` });
    }
    if (this.policy.settings.requireDeviceAssignedToUser && device.assignedTo !== user.id) {
      checks.push({
        code: 'device.not_assigned_to_user',
        message: `Device ${device.id} is not assigned to ${user.id}`,
      });
    }
    if (
      sessionAgeSeconds !== undefined &&
      app.maxSessionMinutes !== undefined &&
      sessionAgeSeconds > app.maxSessionMinutes * 60
    ) {
      checks.push({
        code: 'session.max_age_exceeded',
        message: `Session is ${Math.floor(sessionAgeSeconds / 60)} minutes old; app ${app.id} allows ${app.maxSessionMinutes}`,
      });
    }
    return checks;
  }

  /** Device-state checks only — used by continuous re-evaluation. */
  deviceChecks(device: DeviceRecord): DenialReason[] {
    const checks: DenialReason[] = [];
    if (device.status !== 'active') {
      checks.push({ code: 'device.revoked', message: `Device ${device.id} is revoked` });
    }
    return checks;
  }

  evaluateDevicePosture(
    device: DeviceRecord,
    facts: PostureFacts | null,
    app?: AppPolicy,
    now = Date.now(),
  ): PostureEvaluation {
    const requirements = app ? this.requirementsFor(app) : this.postureBaseline;
    return evaluatePosture(device.id, facts, requirements, { platform: device.platform, now });
  }

  /**
   * Decide access for one app. `facts === null` means no posture data, which
   * fails any mandatory posture check (fail closed).
   */
  decide(
    app: AppPolicy,
    user: AuthenticatedUser,
    device: DeviceRecord,
    facts: PostureFacts | null,
    now = Date.now(),
    sessionAgeSeconds?: number,
  ): AccessDecision {
    const posture = this.evaluateDevicePosture(device, facts, app, now);
    const checks = this.staticChecks(app, user, device, sessionAgeSeconds);
    const reasons = [...checks, ...posture.reasons];
    return { allow: reasons.length === 0, appId: app.id, reasons, posture, checks };
  }
}
