import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validatePolicy, mergePostureRequirements, ConfigError } from '../src/config.ts';
import { PolicyEngine } from '../src/policy/engine.ts';
import type { AuthenticatedUser, DeviceRecord, PolicyFile } from '../src/types.ts';

function basePolicy(): PolicyFile {
  return validatePolicy({
    version: 1,
    settings: { revocationSlaSeconds: 60, postureRecheckSeconds: 5 },
    postureBaseline: { maxReportAgeSeconds: 60, requireDiskEncryption: true },
    apps: [
      {
        id: 'wiki',
        upstream: 'http://127.0.0.1:9000',
        hosts: ['wiki.example.com', 'localhost'],
        paths: ['/wiki'],
        allow: { groups: ['engineering'] },
      },
      {
        id: 'finance',
        upstream: 'http://127.0.0.1:9001',
        hosts: ['localhost'],
        paths: ['/finance'],
        allow: { groups: ['finance'] },
        require: { posture: { minScore: 95 } },
        maxSessionMinutes: 60,
      },
      {
        id: 'wiki-admin',
        upstream: 'http://127.0.0.1:9002',
        hosts: ['localhost'],
        paths: ['/wiki/admin'],
        allow: { users: ['alice'] },
        methods: ['GET', 'POST'],
      },
    ],
  });
}

const user: AuthenticatedUser = { id: 'alice', displayName: 'Alice', groups: ['engineering'], role: 'user' };

function device(overrides: Partial<DeviceRecord> = {}): DeviceRecord {
  return {
    id: 'dev-alice',
    label: 'Alice laptop',
    platform: 'darwin',
    assignedTo: 'alice',
    status: 'active',
    certFingerprint256: 'AA:BB',
    certSubject: 'CN=dev-alice',
    certSerial: '01',
    certNotAfter: '2030-01-01',
    enrolledAt: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

test('most specific path wins', () => {
  const engine = new PolicyEngine(basePolicy());
  assert.equal(engine.findApp('localhost', '/wiki/page')?.id, 'wiki');
  assert.equal(engine.findApp('localhost', '/wiki/admin/users')?.id, 'wiki-admin');
  assert.equal(engine.findApp('localhost', '/finance/q4')?.id, 'finance');
  assert.equal(engine.findApp('localhost', '/nope'), undefined);
  assert.equal(engine.findApp('other.example.com', '/wiki'), undefined);
});

test('method restrictions prevent route selection entirely', () => {
  const engine = new PolicyEngine(basePolicy());
  assert.equal(engine.findApp('localhost', '/wiki/admin', 'DELETE'), undefined);
  assert.equal(engine.findApp('localhost', '/wiki/admin', 'POST')?.id, 'wiki-admin');
});

test('per-app posture requirements merge over the baseline', () => {
  const engine = new PolicyEngine(basePolicy());
  const finance = engine.appById('finance')!;
  const merged = engine.requirementsFor(finance);
  assert.equal(merged.requireDiskEncryption, true); // baseline
  assert.equal(merged.maxReportAgeSeconds, 60); // baseline
  assert.equal(merged.minScore, 95); // app override
});

test('merge treats explicit false as an override, not as absent', () => {
  const merged = mergePostureRequirements(
    { requireDiskEncryption: true, requireEdrRunning: true },
    { requireDiskEncryption: false },
  );
  assert.equal(merged.requireDiskEncryption, false);
  assert.equal(merged.requireEdrRunning, true);
});

test('group membership grants access; absence denies with a reason', () => {
  const engine = new PolicyEngine(basePolicy());
  const wiki = engine.appById('wiki')!;
  const facts = {
    osVersion: '15.1',
    diskEncrypted: true,
    edrInstalled: true,
    edrRunning: true,
    edrLastHeartbeatAt: null,
    reportedAt: new Date().toISOString(),
    source: 'agent' as const,
  };
  const allowed = engine.decide(wiki, user, device(), facts);
  assert.equal(allowed.allow, true);
  const denied = engine.decide(wiki, { ...user, groups: ['finance'] }, device(), facts);
  assert.equal(denied.allow, false);
  assert.deepEqual(denied.reasons.map((reason) => reason.code), ['rbac.user_not_allowed']);
});

test('missing posture data fails closed even when only baseline checks exist', () => {
  const engine = new PolicyEngine(basePolicy());
  const wiki = engine.appById('wiki')!;
  const decision = engine.decide(wiki, user, device(), null);
  assert.equal(decision.allow, false);
  assert.ok(decision.reasons.some((reason) => reason.code === 'posture.missing'));
});

test('revoked device is denied', () => {
  const engine = new PolicyEngine(basePolicy());
  const wiki = engine.appById('wiki')!;
  const decision = engine.decide(wiki, user, device({ status: 'revoked' }), null);
  assert.ok(decision.reasons.some((reason) => reason.code === 'device.revoked'));
});

test('device assigned to someone else is denied', () => {
  const engine = new PolicyEngine(basePolicy());
  const wiki = engine.appById('wiki')!;
  const facts = {
    osVersion: '15.1',
    diskEncrypted: true,
    edrInstalled: true,
    edrRunning: true,
    edrLastHeartbeatAt: new Date().toISOString(),
    reportedAt: new Date().toISOString(),
    source: 'agent' as const,
  };
  const decision = engine.decide(wiki, user, device({ assignedTo: 'bob' }), facts);
  assert.ok(decision.reasons.some((reason) => reason.code === 'device.not_assigned_to_user'));
});

test('app maxSessionMinutes is enforced', () => {
  const engine = new PolicyEngine(basePolicy());
  const finance = engine.appById('finance')!;
  const facts = {
    osVersion: '15.1',
    diskEncrypted: true,
    edrInstalled: true,
    edrRunning: true,
    edrLastHeartbeatAt: new Date().toISOString(),
    reportedAt: new Date().toISOString(),
    source: 'agent' as const,
  };
  const financeUser = { ...user, groups: ['finance'] };
  const fresh = engine.decide(finance, financeUser, device(), facts, Date.now(), 60);
  assert.equal(fresh.allow, true);
  const old = engine.decide(finance, financeUser, device(), facts, Date.now(), 3_700);
  assert.ok(old.reasons.some((reason) => reason.code === 'session.max_age_exceeded'));
});

test('policy validation rejects unsafe or ambiguous configuration', () => {
  const valid = {
    version: 1,
    settings: {},
    apps: [{ id: 'a', upstream: 'http://x', hosts: ['*'], allow: { users: ['u'] } }],
  };
  assert.doesNotThrow(() => validatePolicy(valid));

  const cases: [string, unknown][] = [
    ['missing allow', { ...valid, apps: [{ id: 'a', upstream: 'http://x', hosts: ['*'] }] }],
    ['empty allow', { ...valid, apps: [{ id: 'a', upstream: 'http://x', hosts: ['*'], allow: {} }] }],
    ['bad upstream', { ...valid, apps: [{ ...valid.apps[0], upstream: 'file:///etc/passwd' }] }],
    ['duplicate ids', { ...valid, apps: [valid.apps[0], valid.apps[0]] }],
    ['reserved header', { ...valid, apps: [{ ...valid.apps[0], injectHeaders: { 'X-ZTA-User': 'root' } }] }],
    ['unknown platform', { ...valid, postureBaseline: { minOsVersion: { beos: '1' } } }],
    [
      'recheck not below SLA',
      { ...valid, settings: { revocationSlaSeconds: 5, postureRecheckSeconds: 5 } },
    ],
    ['empty hosts', { ...valid, apps: [{ ...valid.apps[0], hosts: [] }] }],
  ];
  for (const [name, value] of cases) {
    assert.throws(() => validatePolicy(value), ConfigError, name);
  }
});

test('an app with an empty paths list is rejected', () => {
  assert.throws(
    () =>
      validatePolicy({
        version: 1,
        settings: {},
        apps: [{ id: 'a', upstream: 'http://x', hosts: ['*'], paths: [], allow: { users: ['u'] } }],
      }),
    ConfigError,
  );
});
