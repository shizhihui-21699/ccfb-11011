/**
 * Declarative per-application access policy.
 *
 * Rules are evaluated in declaration order; the first rule whose matcher
 * applies wins. If no rule matches, access is denied (default deny). An
 * explicit `deny` rule can therefore be placed above permissive rules to carve
 * out exceptions.
 *
 * Matching is driven by facts assembled at request time: the user's roles and
 * group, the device's id/group, and the device's current posture snapshot.
 * Posture-derived requirements are re-evaluated for every request and by the
 * continuous-authorization loop.
 */
import {
  meetsMinimumVersion,
  osFamily,
  resolveVersionFloor,
  type OsFamily,
  type VersionFloor,
} from '../util/version.ts';

export interface PolicyDocument {
  version: number;
  /** Reason surfaced when no rule matches. */
  defaultDenyReason?: string;
  rules: PolicyRule[];
}

export interface PolicyRule {
  id: string;
  effect: 'allow' | 'deny';
  description?: string;
  /** App ids this rule applies to; `"*"` matches every application. */
  apps: string[];
  /** Conditions on the human identity. All present fields must match. */
  users?: string[];
  groups?: string[];
  roles?: string[];
  /** Conditions on the device identity. */
  deviceGroups?: string[];
  deviceIds?: string[];
  /** Hard posture requirements; failure means the rule does not apply. */
  requireDiskEncrypted?: boolean;
  requireEdrOnline?: boolean;
  requireFirewall?: boolean;
  /** Device OS family allow-list: macos | windows | linux. */
  osFamilies?: ('macos' | 'windows' | 'linux')[];
  /**
   * Minimum OS version, either a bare string (applies to every OS family —
   * avoid on mixed fleets, where the version schemes are not comparable) or a
   * per-family map such as {"macos":"14.2.0","windows":"10.0.19045"}.
   */
  minOsVersion?: VersionFloor;
  /** Posture must be no older than this, in seconds. */
  maxPostureAgeSeconds?: number;
  /** When true, a rule with posture requirements is skipped if posture is missing. */
  allowMissingPosture?: boolean;
}

export interface PolicyFacts {
  appId: string;
  userId: string;
  username: string;
  roles: string[];
  group: string;
  deviceId: string;
  deviceGroup: string | null;
  posture: PostureFacts | null;
  now: Date;
}

export interface PostureFacts {
  osName: string;
  osVersion: string;
  diskEncrypted: boolean;
  edrOnline: boolean;
  firewallEnabled: boolean;
  collectedAt: Date;
}

export interface RequirementResult {
  name: string;
  ok: boolean;
  detail: string;
}

export interface PolicyDecision {
  allow: boolean;
  /** Stable code for audit and UI, e.g. `no_matching_rule`. */
  code: string;
  reason: string;
  ruleId: string | null;
  requirements: RequirementResult[];
}

/**
 * Normalizes a policy document: validates shapes, applies defaults, and makes
 * every rule's app list explicit. Throws on malformed input so a bad policy
 * file fails startup rather than silently opening access.
 */
export function normalizePolicy(input: unknown, defaultMinOsVersion: VersionFloor | undefined): PolicyDocument {
  const floor = parseVersionFloor(defaultMinOsVersion, 'thresholds.minOsVersion');
  const doc = input as Partial<PolicyDocument> | null;
  if (doc === null || typeof doc !== 'object' || !Array.isArray(doc.rules)) {
    throw new PolicyError('policy must be an object with a "rules" array');
  }
  const ids = new Set<string>();
  const rules: PolicyRule[] = doc.rules.map((candidate, index) => {
    return normalizeRule(candidate, index, floor, ids);
  });
  return {
    version: typeof doc.version === 'number' ? doc.version : 1,
    defaultDenyReason: doc.defaultDenyReason ?? 'No policy rule permits this access.',
    rules,
  };
}

function normalizeRule(
  candidate: unknown,
  index: number,
  defaultMinOsVersion: VersionFloor | undefined,
  ids: Set<string>,
): PolicyRule {
  if (candidate === null || typeof candidate !== 'object') {
    throw new PolicyError(`rule ${index} must be an object`);
  }
  const raw = candidate as Partial<PolicyRule>;
  const id = typeof raw.id === 'string' && raw.id.trim() !== '' ? raw.id.trim() : `rule-${index + 1}`;
  if (ids.has(id)) throw new PolicyError(`duplicate rule id "${id}"`);
  ids.add(id);
  if (raw.effect !== 'allow' && raw.effect !== 'deny') {
    throw new PolicyError(`rule "${id}" must have effect "allow" or "deny"`);
  }
  if (!Array.isArray(raw.apps) || raw.apps.length === 0) {
    throw new PolicyError(`rule "${id}" must list at least one app id`);
  }
  for (const app of raw.apps) {
    if (typeof app !== 'string' || (app !== '*' && !/^[a-z0-9][a-z0-9-]{0,63}$/.test(app))) {
      throw new PolicyError(`rule "${id}" has an invalid app id`);
    }
  }
  const list = (value: unknown, field: string): string[] | undefined => {
    if (value === undefined) return undefined;
    if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
      throw new PolicyError(`rule "${id}" field "${field}" must be an array of strings`);
    }
    return value as string[];
  };
  const flag = (value: unknown, field: string): boolean | undefined => {
    if (value === undefined) return undefined;
    if (typeof value !== 'boolean') throw new PolicyError(`rule "${id}" field "${field}" must be boolean`);
    return value;
  };
  const osFamilies = list(raw.osFamilies as unknown, 'osFamilies') as
    | ('macos' | 'windows' | 'linux')[]
    | undefined;
  if (osFamilies?.some((family) => !['macos', 'windows', 'linux'].includes(family))) {
    throw new PolicyError(`rule "${id}" field "osFamilies" must contain macos, windows or linux`);
  }
  const minOsVersion = parseVersionFloor(raw.minOsVersion, `rule "${id}" field "minOsVersion"`);
  const inheritedFloor = parseVersionFloor(defaultMinOsVersion, 'thresholds.minOsVersion');
  if (
    raw.maxPostureAgeSeconds !== undefined &&
    (typeof raw.maxPostureAgeSeconds !== 'number' || raw.maxPostureAgeSeconds <= 0)
  ) {
    throw new PolicyError(`rule "${id}" field "maxPostureAgeSeconds" must be a positive number`);
  }
  return {
    id,
    effect: raw.effect,
    description: raw.description,
    apps: [...new Set(raw.apps as string[])],
    users: list(raw.users as unknown, 'users'),
    groups: list(raw.groups as unknown, 'groups'),
    roles: list(raw.roles as unknown, 'roles'),
    deviceGroups: list(raw.deviceGroups as unknown, 'deviceGroups'),
    deviceIds: list(raw.deviceIds as unknown, 'deviceIds'),
    requireDiskEncrypted: flag(raw.requireDiskEncrypted as unknown, 'requireDiskEncrypted'),
    requireEdrOnline: flag(raw.requireEdrOnline as unknown, 'requireEdrOnline'),
    requireFirewall: flag(raw.requireFirewall as unknown, 'requireFirewall'),
    osFamilies,
    minOsVersion: minOsVersion ?? inheritedFloor,
    maxPostureAgeSeconds: raw.maxPostureAgeSeconds,
    allowMissingPosture: flag(raw.allowMissingPosture as unknown, 'allowMissingPosture') ?? false,
  };
}

export class PolicyError extends Error {
  override name = 'PolicyError';
}

/** True when any subject condition excludes the user. */
function subjectMatches(rule: PolicyRule, facts: PolicyFacts): RequirementResult | null {
  if (rule.users && !rule.users.includes(facts.username)) {
    return { name: 'user', ok: false, detail: `user ${facts.username} is not in the rule's user list` };
  }
  if (rule.groups && !rule.groups.includes(facts.group)) {
    return { name: 'group', ok: false, detail: `group ${facts.group} is not allowed` };
  }
  if (rule.roles && !facts.roles.some((role) => rule.roles!.includes(role))) {
    return { name: 'role', ok: false, detail: `no required role (${rule.roles.join(', ')})` };
  }
  if (rule.deviceGroups && (facts.deviceGroup === null || !rule.deviceGroups.includes(facts.deviceGroup))) {
    return { name: 'deviceGroup', ok: false, detail: 'device group is not allowed' };
  }
  if (rule.deviceIds && !rule.deviceIds.includes(facts.deviceId)) {
    return { name: 'deviceId', ok: false, detail: 'device id is not in the rule list' };
  }
  return null;
}

/** Validates a version floor (string or per-family map). */
export function parseVersionFloor(value: unknown, context: string): VersionFloor | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'string') {
    if (!versionIsParseable(value)) throw new PolicyError(`${context} is not a version string`);
    return value;
  }
  if (value !== null && typeof value === 'object') {
    const allowed: OsFamily[] = ['macos', 'windows', 'linux'];
    const record = value as Record<string, unknown>;
    for (const [key, entry] of Object.entries(record)) {
      if (!allowed.includes(key as OsFamily)) {
        throw new PolicyError(`${context} has unknown OS family "${key}"`);
      }
      if (typeof entry !== 'string' || !versionIsParseable(entry)) {
        throw new PolicyError(`${context}.${key} is not a version string`);
      }
    }
    return record as VersionFloor;
  }
  throw new PolicyError(`${context} must be a version string or an object of per-OS versions`);
}

function versionIsParseable(value: string): boolean {
  return /^\s*v?(\d+(\.\d+)*)$/.test(value.trim());
}

/** Applies the rule's posture requirements; returns every requirement result. */
function postureResults(rule: PolicyRule, facts: PolicyFacts, globalMinOs: VersionFloor | undefined): RequirementResult[] {
  const results: RequirementResult[] = [];
  const posture = facts.posture;
  if (posture === null) {
    if (rule.allowMissingPosture) return results;
    return [{ name: 'posture', ok: false, detail: 'no posture report on file' }];
  }
  const ageSeconds = Math.floor((facts.now.getTime() - posture.collectedAt.getTime()) / 1000);
  const maxAge = rule.maxPostureAgeSeconds ?? Number.POSITIVE_INFINITY;
  results.push({
    name: 'postureFreshness',
    ok: ageSeconds <= maxAge && ageSeconds >= -300,
    detail: `posture is ${ageSeconds}s old (limit ${Number.isFinite(maxAge) ? `${maxAge}s` : 'none'})`,
  });
  const family = osFamily(posture.osName);
  const minimum = resolveVersionFloor(rule.minOsVersion ?? globalMinOs, family as OsFamily);
  if (minimum === null) {
    results.push({
      name: 'osVersion',
      ok: false,
      detail: `no minimum OS configured for ${family}; cannot verify version ${posture.osVersion}`,
    });
  } else {
    results.push({
      name: 'osVersion',
      ok: meetsMinimumVersion(posture.osVersion, minimum),
      detail: `${posture.osName} ${posture.osVersion} vs ${family} minimum ${minimum}`,
    });
  }
  if (rule.osFamilies) {
    results.push({
      name: 'osFamily',
      ok: rule.osFamilies.includes(family as 'macos' | 'windows' | 'linux'),
      detail: `os family ${family} not in (${rule.osFamilies.join(', ')})`,
    });
  }
  if (rule.requireDiskEncrypted) {
    results.push({
      name: 'diskEncrypted',
      ok: posture.diskEncrypted,
      detail: posture.diskEncrypted ? 'disk encryption is on' : 'disk encryption is off',
    });
  }
  if (rule.requireEdrOnline) {
    results.push({
      name: 'edrOnline',
      ok: posture.edrOnline,
      detail: posture.edrOnline ? 'EDR is online' : 'EDR is offline or not reporting',
    });
  }
  if (rule.requireFirewall) {
    results.push({
      name: 'firewall',
      ok: posture.firewallEnabled,
      detail: posture.firewallEnabled ? 'host firewall is enabled' : 'host firewall is disabled',
    });
  }
  return results;
}

/** Evaluates a normalized policy for one access request. */
export function evaluatePolicy(
  policy: PolicyDocument,
  facts: PolicyFacts,
  globalMinOsVersion: VersionFloor | undefined,
): PolicyDecision {
  const requirements: RequirementResult[] = [];

  for (const rule of policy.rules) {
    if (!rule.apps.includes('*') && !rule.apps.includes(facts.appId)) continue;
    const subject = subjectMatches(rule, facts);
    if (subject !== null) {
      requirements.push(subject);
      continue;
    }
    const posture = postureResults(rule, facts, globalMinOsVersion);
    const failed = posture.filter((item) => !item.ok);
    if (failed.length > 0) {
      requirements.push(...failed);
      continue;
    }
    requirements.push(...posture);
    if (rule.effect === 'deny') {
      // First matching rule wins — an applicable deny must stop evaluation
      // here, otherwise a later allow rule would silently override it.
      return {
        allow: false,
        code: 'denied_by_rule',
        reason: rule.description
          ? `Denied by rule "${rule.id}": ${rule.description}`
          : `Denied by rule "${rule.id}".`,
        ruleId: rule.id,
        requirements,
      };
    }
    return {
      allow: true,
      code: 'allowed_by_rule',
      reason: rule.description
        ? `Allowed by rule "${rule.id}": ${rule.description}`
        : `Allowed by rule "${rule.id}".`,
      ruleId: rule.id,
      requirements,
    };
  }

  return {
    allow: false,
    code: 'no_matching_rule',
    reason: policy.defaultDenyReason ?? 'No policy rule permits this access.',
    ruleId: null,
    requirements,
  };
}

/**
 * Continuous re-evaluation helper: returns true when the last recorded
 * decision was allow and the fresh decision differs, i.e. the grant should be
 * revoked. Kept pure so the loop logic stays testable.
 */
export function requiresRevocation(previousDecision: 'allow' | 'deny', next: PolicyDecision): boolean {
  return previousDecision === 'allow' && !next.allow;
}
