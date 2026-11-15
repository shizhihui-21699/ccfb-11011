/**
 * Authorization decisions.
 *
 * A request is allowed only when BOTH of these hold:
 *
 *   1. Device baseline — a device-level trust floor that is independent of
 *      application policy: posture must exist, be fresh, report disk
 *      encryption and a live EDR. A device that fails the baseline loses every
 *      session and grant it holds.
 *   2. Application policy — the declarative rules in config/policy.json.
 *
 * Keeping the baseline separate means policy authors cannot accidentally
 * grant access to a device their own rules forgot to constrain, and a device
 * going bad is handled in one place.
 */
import type { Config } from '../config.ts';
import type { DeviceStore, PostureStore, UserStore } from '../store/repositories.ts';
import type { DeviceRecord, PostureSnapshotRecord, UserRecord } from '../store/types.ts';
import {
  evaluatePolicy,
  type PolicyDecision,
  type PolicyDocument,
  type PolicyFacts,
  type RequirementResult,
} from '../policy/engine.ts';

export interface AccessRequest {
  user: UserRecord;
  device: DeviceRecord;
  appId: string;
  now: Date;
  /** Overrides the cached snapshot; used by the revalidator for a fresh read. */
  posture?: PostureSnapshotRecord | null;
}

export interface AccessDecision {
  allow: boolean;
  code: string;
  reason: string;
  ruleId: string | null;
  requirements: RequirementResult[];
  /** True when the failure is device-wide and must kill the session too. */
  deviceTrustFailure: boolean;
  posture: PostureSnapshotRecord | null;
}

export interface BaselineResult {
  ok: boolean;
  code: string;
  reason: string;
  requirements: RequirementResult[];
}

/**
 * Device trust floor. Posture is supplied by the caller so the same function
 * serves both live requests (cached snapshot) and the log proves freshness
 * with an explicit timestamp.
 */
export function evaluateBaseline(
  posture: PostureSnapshotRecord | null,
  config: Config,
  now: Date,
): BaselineResult {
  if (posture === null) {
    return {
      ok: false,
      code: 'posture_missing',
      reason: 'No posture report has ever been received for this device.',
      requirements: [{ name: 'posture', ok: false, detail: 'missing' }],
    };
  }
  const requirements: RequirementResult[] = [];
  const ageSeconds = Math.floor((now.getTime() - new Date(posture.collectedAt).getTime()) / 1000);
  const maxAge = config.thresholds.postureMaxAgeSeconds;
  // Reject reports from the future beyond a small skew: a forged timestamp
  // would otherwise keep a stale device "fresh" indefinitely.
  const fresh = ageSeconds <= maxAge && ageSeconds >= -300;
  requirements.push({
    name: 'postureFreshness',
    ok: fresh,
    detail: `collected ${ageSeconds}s ago (max ${maxAge}s)`,
  });
  requirements.push({
    name: 'diskEncrypted',
    ok: posture.diskEncrypted,
    detail: posture.diskEncrypted ? 'disk encryption on' : 'disk encryption off',
  });
  requirements.push({
    name: 'edrOnline',
    ok: posture.edrOnline,
    detail: posture.edrOnline ? 'EDR online' : 'EDR offline',
  });
  const failed = requirements.filter((requirement) => !requirement.ok);
  if (failed.length === 0) {
    return { ok: true, code: 'baseline_ok', reason: 'Device baseline satisfied.', requirements };
  }
  const stale = failed.some((requirement) => requirement.name === 'postureFreshness');
  return {
    ok: false,
    code: stale ? 'posture_stale' : 'device_untrusted',
    reason: stale
      ? `Posture is stale (${ageSeconds}s old, limit ${maxAge}s).`
      : `Device fails the trust baseline: ${failed.map((item) => item.name).join(', ')}.`,
    requirements,
  };
}

export class AccessController {
  private readonly users: UserStore;
  private readonly devices: DeviceStore;
  private readonly posture: PostureStore;
  private readonly config: Config;

  constructor(deps: {
    users: UserStore;
    devices: DeviceStore;
    posture: PostureStore;
    config: Config;
  }) {
    this.users = deps.users;
    this.devices = deps.devices;
    this.posture = deps.posture;
    this.config = deps.config;
  }

  /** Builds the fact set the policy engine evaluates. */
  factsFor(request: AccessRequest): PolicyFacts {
    const posture = request.posture === undefined ? this.posture.get(request.device.id) : request.posture;
    return {
      appId: request.appId,
      userId: request.user.id,
      username: request.user.username,
      roles: request.user.roles,
      group: request.user.group,
      deviceId: request.device.id,
      deviceGroup: request.device.group,
      posture:
        posture === null
          ? null
          : {
              osName: posture.osName,
              osVersion: posture.osVersion,
              diskEncrypted: posture.diskEncrypted,
              edrOnline: posture.edrOnline,
              firewallEnabled: posture.firewallEnabled,
              collectedAt: new Date(posture.collectedAt),
            },
      now: request.now,
    };
  }

  /** Full decision: device baseline, then application policy. */
  decide(request: AccessRequest, policy: PolicyDocument): AccessDecision {
    const posture = request.posture === undefined ? this.posture.get(request.device.id) : request.posture;
    if (request.user.disabled) {
      return {
        allow: false,
        code: 'user_disabled',
        reason: 'The user account is disabled.',
        ruleId: null,
        requirements: [],
        deviceTrustFailure: false,
        posture,
      };
    }
    if (request.device.status !== 'enrolled') {
      return {
        allow: false,
        code: 'device_revoked',
        reason: request.device.revokedReason ?? 'The device is revoked.',
        ruleId: null,
        requirements: [],
        deviceTrustFailure: true,
        posture,
      };
    }
    if (request.device.ownerUserId !== null && request.device.ownerUserId !== request.user.id) {
      return {
        allow: false,
        code: 'device_owner_mismatch',
        reason: 'The certificate is registered to a different user.',
        ruleId: null,
        requirements: [],
        deviceTrustFailure: true,
        posture,
      };
    }

    const baseline = evaluateBaseline(posture, this.config, request.now);
    if (!baseline.ok) {
      return {
        allow: false,
        code: baseline.code,
        reason: baseline.reason,
        ruleId: null,
        requirements: baseline.requirements,
        deviceTrustFailure: true,
        posture,
      };
    }

    const decision: PolicyDecision = evaluatePolicy(
      policy,
      this.factsFor({ ...request, posture }),
      this.config.thresholds.minOsVersion,
    );
    return {
      allow: decision.allow,
      code: decision.code,
      reason: decision.reason,
      ruleId: decision.ruleId,
      requirements: [...baseline.requirements, ...decision.requirements],
      deviceTrustFailure: false,
      posture,
    };
  }

  /**
   * Re-evaluates an existing grant. Returns a decision whose `allow` indicates
   * whether the grant should stay live. Missing user/device rows fail closed.
   */
  revalidate(
    grant: { userId: string; deviceId: string; appId: string },
    policy: PolicyDocument,
    now: Date,
  ): AccessDecision {
    const user = this.users.findById(grant.userId);
    const device = this.devices.findById(grant.deviceId);
    if (user === null) {
      return {
        allow: false,
        code: 'user_missing',
        reason: 'The user no longer exists.',
        ruleId: null,
        requirements: [],
        deviceTrustFailure: true,
        posture: null,
      };
    }
    if (device === null) {
      return {
        allow: false,
        code: 'device_missing',
        reason: 'The device is no longer enrolled.',
        ruleId: null,
        requirements: [],
        deviceTrustFailure: true,
        posture: null,
      };
    }
    return this.decide({ user, device, appId: grant.appId, now }, policy);
  }
}
