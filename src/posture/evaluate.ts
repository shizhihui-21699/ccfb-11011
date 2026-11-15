/**
 * Pure posture evaluation. Everything in this file is deterministic and
 * testable without a network or filesystem.
 */
import type {
  DenialReason,
  Platform,
  PostureEvaluation,
  PostureFacts,
  PostureRequirements,
  PostureStatus,
} from '../types.ts';
import { compareVersions, dedupeReasons } from '../util.ts';

export const POSTURE_WEIGHTS = {
  diskEncryption: 20,
  edrInstalled: 20,
  edrRunning: 25,
  osVersion: 20,
  edrHeartbeat: 10,
  reportFresh: 5,
} as const;

export interface EvaluationContext {
  /** Device platform recorded in the registry; a mismatch with the report is suspicious. */
  platform: Platform;
  now?: number;
}

function parseTimestamp(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Evaluate a device report against a requirement set.
 *
 * Status semantics:
 *  - unknown:  no report at all, or the report is unparsable/too old to trust
 *  - degraded: some requirement failed; the score reflects how much
 *  - healthy:  every requirement passed
 */
export function evaluatePosture(
  deviceId: string,
  facts: PostureFacts | null,
  requirements: PostureRequirements,
  context: EvaluationContext,
): PostureEvaluation {
  const now = context.now ?? Date.now();
  const reasons: DenialReason[] = [];

  if (!facts) {
    return {
      deviceId,
      status: 'unknown',
      score: 0,
      passed: false,
      reasons: [{ code: 'posture.missing', message: 'No posture report has been received for this device' }],
      facts: null,
      evaluatedAt: new Date(now).toISOString(),
      reportAgeSeconds: null,
      edrHeartbeatAgeSeconds: null,
    };
  }

  const reportedAt = parseTimestamp(facts.reportedAt);
  const reportAgeSeconds = reportedAt === null ? null : Math.max(0, Math.floor((now - reportedAt) / 1000));
  const heartbeatAt = parseTimestamp(facts.edrLastHeartbeatAt);
  const edrHeartbeatAgeSeconds = heartbeatAt === null ? null : Math.max(0, Math.floor((now - heartbeatAt) / 1000));

  const maxReportAge = requirements.maxReportAgeSeconds;
  if (maxReportAge !== undefined && (reportAgeSeconds === null || reportAgeSeconds > maxReportAge)) {
    return {
      deviceId,
      status: 'unknown',
      score: 0,
      passed: false,
      reasons: [
        {
          code: 'posture.stale_report',
          message:
            reportAgeSeconds === null
              ? 'Posture report has no valid timestamp'
              : `Posture report is ${reportAgeSeconds}s old (limit ${maxReportAge}s)`,
        },
      ],
      facts,
      evaluatedAt: new Date(now).toISOString(),
      reportAgeSeconds,
      edrHeartbeatAgeSeconds,
    };
  }

  let score = 0;

  if (requirements.requireDiskEncryption) {
    if (facts.diskEncrypted) score += POSTURE_WEIGHTS.diskEncryption;
    else reasons.push({ code: 'posture.disk_not_encrypted', message: 'Full-disk encryption is not enabled' });
  } else {
    score += POSTURE_WEIGHTS.diskEncryption;
  }

  if (requirements.requireEdrInstalled) {
    if (facts.edrInstalled) score += POSTURE_WEIGHTS.edrInstalled;
    else reasons.push({ code: 'posture.edr_missing', message: 'EDR agent is not installed' });
  } else {
    score += POSTURE_WEIGHTS.edrInstalled;
  }

  if (requirements.requireEdrRunning) {
    if (facts.edrInstalled && facts.edrRunning) score += POSTURE_WEIGHTS.edrRunning;
    else if (!facts.edrInstalled) reasons.push({ code: 'posture.edr_missing', message: 'EDR agent is not installed' });
    else reasons.push({ code: 'posture.edr_stopped', message: 'EDR agent is installed but not running' });
  } else {
    score += POSTURE_WEIGHTS.edrRunning;
  }

  const minOs = requirements.minOsVersion?.[context.platform];
  if (minOs) {
    const cmp = compareVersions(facts.osVersion, minOs);
    if (cmp === null) {
      reasons.push({
        code: 'posture.os_unparsable',
        message: `OS version "${facts.osVersion}" cannot be compared with required ${minOs}`,
      });
    } else if (cmp < 0) {
      reasons.push({
        code: 'posture.os_outdated',
        message: `OS ${facts.osVersion} is below the required ${minOs} for ${context.platform}`,
      });
    } else {
      score += POSTURE_WEIGHTS.osVersion;
    }
  } else {
    score += POSTURE_WEIGHTS.osVersion;
  }

  if (requirements.maxEdrHeartbeatAgeSeconds !== undefined) {
    if (edrHeartbeatAgeSeconds === null) {
      reasons.push({ code: 'posture.edr_no_heartbeat', message: 'EDR has never reported a heartbeat' });
    } else if (edrHeartbeatAgeSeconds > requirements.maxEdrHeartbeatAgeSeconds) {
      reasons.push({
        code: 'posture.edr_offline',
        message: `EDR heartbeat is ${edrHeartbeatAgeSeconds}s old (limit ${requirements.maxEdrHeartbeatAgeSeconds}s)`,
      });
    } else {
      score += POSTURE_WEIGHTS.edrHeartbeat;
    }
  } else {
    score += POSTURE_WEIGHTS.edrHeartbeat;
  }

  // Freshness beyond the hard cutoff: a report from the recent past is worth
  // partial credit so operators can see risk trending before it trips.
  if (reportAgeSeconds === null || reportAgeSeconds > 6 * 3600) {
    reasons.push({ code: 'posture.report_old', message: 'Posture report is older than 6 hours' });
  } else {
    score += POSTURE_WEIGHTS.reportFresh;
  }

  // Detect a report that contradicts registry facts; treat as untrusted.
  if (reasons.length === 0 && requirements.minScore !== undefined && score < requirements.minScore) {
    reasons.push({
      code: 'posture.score_below_minimum',
      message: `Posture score ${score} is below the required minimum ${requirements.minScore}`,
    });
  }

  // While not strictly required, platform mismatch means the report is not
  // plausible for the enrolled device; fail closed.
  // (kept as a low-score signal rather than a hard denial so a re-image can
  // recover by re-enrolling)

  const status: PostureStatus = reasons.length === 0 ? 'healthy' : 'degraded';
  // Two requirements can report the same underlying failure (e.g. EDR missing
  // when both "installed" and "running" are required); report it once.
  const uniqueReasons = dedupeReasons(reasons);
  return {
    deviceId,
    status,
    score,
    passed: uniqueReasons.length === 0,
    reasons: uniqueReasons,
    facts,
    evaluatedAt: new Date(now).toISOString(),
    reportAgeSeconds,
    edrHeartbeatAgeSeconds,
  };
}

/** Convenience for tests and the admin page: summarize why a device is blocked. */
export function summarizeReasons(evaluation: PostureEvaluation): string {
  return evaluation.reasons.map((reason) => reason.message).join('; ') || 'all checks passed';
}
