import * as fs from 'fs';
import * as path from 'path';

export interface PostureRequirements {
  minOsVersion?: string;
  diskEncrypted?: boolean;
  edrOnline?: boolean;
  /** posture report must be no older than this many seconds */
  maxPostureAgeSec?: number;
}

export interface AppPolicy {
  upstream: string;
  allowUsers: string[];
  require: PostureRequirements;
}

export interface PolicyConfig {
  apps: Record<string, AppPolicy>;
}

export interface DevicePosture {
  deviceId: string;
  osVersion: string;
  diskEncrypted: boolean;
  edrOnline: boolean;
  reportedAt: number; // epoch ms
}

export function loadPolicies(): PolicyConfig {
  const p = path.join(__dirname, '..', 'config', 'policies.json');
  return JSON.parse(fs.readFileSync(p, 'utf8')) as PolicyConfig;
}

/** Compare dotted versions: returns true if actual >= required. */
export function versionAtLeast(actual: string, required: string): boolean {
  const a = actual.split('.').map((n) => parseInt(n, 10) || 0);
  const r = required.split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(a.length, r.length); i++) {
    const av = a[i] ?? 0;
    const rv = r[i] ?? 0;
    if (av > rv) return true;
    if (av < rv) return false;
  }
  return true;
}

export interface Decision {
  allow: boolean;
  reasons: string[];
}

/** Evaluate one app's policy against a user and a device posture snapshot. */
export function evaluate(
  policy: AppPolicy,
  user: string,
  posture: DevicePosture | null,
  now = Date.now(),
): Decision {
  const reasons: string[] = [];

  if (!policy.allowUsers.includes(user)) {
    reasons.push(`user ${user} is not in allowUsers`);
  }

  if (!posture) {
    reasons.push('no posture report for device');
  } else {
    const req = policy.require;
    if (req.minOsVersion && !versionAtLeast(posture.osVersion, req.minOsVersion)) {
      reasons.push(`osVersion ${posture.osVersion} < required ${req.minOsVersion}`);
    }
    if (req.diskEncrypted === true && !posture.diskEncrypted) {
      reasons.push('disk encryption is off');
    }
    if (req.edrOnline === true && !posture.edrOnline) {
      reasons.push('EDR agent is offline');
    }
    if (req.maxPostureAgeSec !== undefined) {
      const ageSec = (now - posture.reportedAt) / 1000;
      if (ageSec > req.maxPostureAgeSec) {
        reasons.push(
          `posture report is stale (${Math.round(ageSec)}s old > ${req.maxPostureAgeSec}s)`,
        );
      }
    }
  }

  return { allow: reasons.length === 0, reasons };
}
