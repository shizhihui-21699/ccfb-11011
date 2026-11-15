import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePosture } from '../src/posture/evaluate.ts';
import { validateReport } from '../src/postureService.ts';
import type { PostureFacts, PostureRequirements } from '../src/types.ts';

const NOW = Date.parse('2026-01-01T12:00:00Z');

function facts(overrides: Partial<PostureFacts> = {}): PostureFacts {
  return {
    osVersion: '15.1.0',
    diskEncrypted: true,
    edrInstalled: true,
    edrRunning: true,
    edrLastHeartbeatAt: new Date(NOW - 5_000).toISOString(),
    reportedAt: new Date(NOW - 10_000).toISOString(),
    agentVersion: '1.0.0',
    source: 'agent',
    ...overrides,
  };
}

const REQUIREMENTS: PostureRequirements = {
  minOsVersion: { darwin: '14.0' },
  requireDiskEncryption: true,
  requireEdrInstalled: true,
  requireEdrRunning: true,
  maxEdrHeartbeatAgeSeconds: 15,
  maxReportAgeSeconds: 60,
};

const ctx = { platform: 'darwin' as const, now: NOW };

test('healthy device passes with a full score', () => {
  const result = evaluatePosture('dev1', facts(), REQUIREMENTS, ctx);
  assert.equal(result.status, 'healthy');
  assert.equal(result.passed, true);
  assert.equal(result.score, 100);
  assert.deepEqual(result.reasons, []);
});

test('missing report fails closed as unknown', () => {
  const result = evaluatePosture('dev1', null, REQUIREMENTS, ctx);
  assert.equal(result.status, 'unknown');
  assert.equal(result.passed, false);
  assert.equal(result.reasons[0].code, 'posture.missing');
});

test('stale report is unknown, not merely degraded', () => {
  const result = evaluatePosture('dev1', facts({ reportedAt: new Date(NOW - 120_000).toISOString() }), REQUIREMENTS, ctx);
  assert.equal(result.status, 'unknown');
  assert.equal(result.reasons[0].code, 'posture.stale_report');
});

test('every failed requirement is reported, not just the first', () => {
  const result = evaluatePosture(
    'dev1',
    facts({
      diskEncrypted: false,
      edrRunning: false,
      osVersion: '13.6.0',
      edrLastHeartbeatAt: new Date(NOW - 600_000).toISOString(),
    }),
    REQUIREMENTS,
    ctx,
  );
  const codes = result.reasons.map((reason) => reason.code).sort();
  assert.deepEqual(codes, [
    'posture.disk_not_encrypted',
    'posture.edr_offline',
    'posture.edr_stopped',
    'posture.os_outdated',
  ]);
  assert.equal(result.status, 'degraded');
  assert.ok(result.score < 60);
});

test('EDR stopped but installed is distinct from EDR missing', () => {
  const stopped = evaluatePosture('dev1', facts({ edrRunning: false }), REQUIREMENTS, ctx);
  assert.deepEqual(stopped.reasons.map((reason) => reason.code), ['posture.edr_stopped']);
  const missing = evaluatePosture('dev1', facts({ edrInstalled: false, edrRunning: false }), REQUIREMENTS, ctx);
  assert.deepEqual(missing.reasons.map((reason) => reason.code), ['posture.edr_missing']);
});

test('unparsable OS version fails closed', () => {
  const result = evaluatePosture('dev1', facts({ osVersion: 'unknown-build' }), REQUIREMENTS, ctx);
  assert.ok(result.reasons.some((reason) => reason.code === 'posture.os_unparsable'));
});

test('requirements not enabled do not fail the device', () => {
  const result = evaluatePosture(
    'dev1',
    facts({ diskEncrypted: false, edrRunning: false }),
    { maxReportAgeSeconds: 60 },
    ctx,
  );
  assert.equal(result.passed, true);
});

test('minScore is enforced only when other checks pass', () => {
  const lenient = evaluatePosture('dev1', facts({ edrRunning: false }), { ...REQUIREMENTS, minScore: 99 }, ctx);
  assert.ok(lenient.reasons.some((reason) => reason.code === 'posture.edr_stopped'));
  const passing = evaluatePosture('dev1', facts(), { ...REQUIREMENTS, minScore: 99 }, ctx);
  assert.equal(passing.passed, true);
  const tooStrict = evaluatePosture('dev1', facts(), { ...REQUIREMENTS, minScore: 101 }, ctx);
  assert.ok(tooStrict.reasons.some((reason) => reason.code === 'posture.score_below_minimum'));
});

test('EDR heartbeat age is measured, not trusted from a boolean', () => {
  const result = evaluatePosture(
    'dev1',
    facts({ edrRunning: true, edrLastHeartbeatAt: new Date(NOW - 20_000).toISOString() }),
    REQUIREMENTS,
    ctx,
  );
  assert.equal(result.edrHeartbeatAgeSeconds, 20);
  assert.ok(result.reasons.some((reason) => reason.code === 'posture.edr_offline'));
});

// --- posture service report validation -------------------------------------

test('report validation rejects malformed payloads', () => {
  const valid = {
    deviceId: 'dev-alice',
    platform: 'darwin',
    osVersion: '15.1.0',
    diskEncrypted: true,
    edrInstalled: true,
    edrRunning: true,
    edrLastHeartbeatAt: new Date().toISOString(),
    reportedAt: new Date().toISOString(),
  };
  assert.doesNotThrow(() => validateReport(valid));
  const bad: unknown[] = [
    null,
    { ...valid, deviceId: '../etc' },
    { ...valid, platform: 'solaris' },
    { ...valid, osVersion: '' },
    { ...valid, diskEncrypted: 'yes' },
    { ...valid, reportedAt: 'yesterday' },
    { ...valid, edrLastHeartbeatAt: 'soon' },
    { ...valid, osVersion: 'x'.repeat(65) },
  ];
  for (const payload of bad) assert.throws(() => validateReport(payload));
});

test('reportedAt is stamped by the service, not the agent', () => {
  const now = Date.parse('2026-01-01T12:00:00Z');
  const result = validateReport(
    {
      deviceId: 'dev-alice',
      platform: 'darwin',
      osVersion: '15.1.0',
      diskEncrypted: true,
      edrInstalled: true,
      edrRunning: true,
      // An agent claiming a future report time must not appear fresher.
      reportedAt: '2030-01-01T00:00:00Z',
      edrLastHeartbeatAt: '2030-01-01T00:00:00Z',
    },
    now,
  );
  assert.equal(result.facts.reportedAt, '2026-01-01T12:00:00.000Z');
  assert.equal(result.facts.edrLastHeartbeatAt, '2026-01-01T12:00:00.000Z');
});
