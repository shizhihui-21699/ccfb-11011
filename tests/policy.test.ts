import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  evaluatePolicy,
  normalizePolicy,
  PolicyError,
  requiresRevocation,
  type PolicyFacts,
} from '../src/policy/engine.ts';

const FLOOR = { macos: '14.0.0', windows: '10.0.19045', linux: '5.15.0' };

function facts(overrides: Partial<PolicyFacts> = {}): PolicyFacts {
  return {
    appId: 'wiki',
    userId: 'usr_1',
    username: 'alice',
    roles: ['employee'],
    group: 'engineering',
    deviceId: 'dev-1',
    deviceGroup: 'laptop',
    posture: {
      osName: 'macOS',
      osVersion: '15.2.0',
      diskEncrypted: true,
      edrOnline: true,
      firewallEnabled: true,
      collectedAt: new Date('2026-01-01T00:00:00Z'),
    },
    now: new Date('2026-01-01T00:00:30Z'),
    ...overrides,
  };
}

const basePolicy = normalizePolicy(
  {
    version: 1,
    rules: [
      { id: 'wiki', effect: 'allow', apps: ['wiki'], roles: ['employee', 'admin'] },
      {
        id: 'payroll',
        effect: 'allow',
        apps: ['payroll'],
        groups: ['finance'],
        requireDiskEncrypted: true,
        requireEdrOnline: true,
      },
    ],
  },
  FLOOR,
);

test('deny-by-default when no rule matches', () => {
  const decision = evaluatePolicy(basePolicy, facts({ appId: 'unknown-app' }), FLOOR);
  assert.equal(decision.allow, false);
  assert.equal(decision.code, 'no_matching_rule');
});

test('allows when subject and posture match', () => {
  const decision = evaluatePolicy(basePolicy, facts(), FLOOR);
  assert.equal(decision.allow, true);
  assert.equal(decision.ruleId, 'wiki');
});

test('role mismatch falls through to default deny', () => {
  const decision = evaluatePolicy(basePolicy, facts({ roles: ['contractor'] }), FLOOR);
  assert.equal(decision.allow, false);
  assert.equal(decision.code, 'no_matching_rule');
});

test('group mismatch denies payroll', () => {
  const decision = evaluatePolicy(basePolicy, facts({ appId: 'payroll', group: 'engineering' }), FLOOR);
  assert.equal(decision.allow, false);
});

test('disk encryption requirement fails closed', () => {
  const decision = evaluatePolicy(
    basePolicy,
    facts({
      appId: 'payroll',
      group: 'finance',
      posture: { ...facts().posture!, diskEncrypted: false },
    }),
    FLOOR,
  );
  assert.equal(decision.allow, false);
  assert.equal(decision.code, 'no_matching_rule');
  assert.ok(decision.requirements.some((req) => req.name === 'diskEncrypted' && !req.ok));
});

test('EDR offline denies payroll', () => {
  const decision = evaluatePolicy(
    basePolicy,
    facts({ appId: 'payroll', group: 'finance', posture: { ...facts().posture!, edrOnline: false } }),
    FLOOR,
  );
  assert.equal(decision.allow, false);
});

test('missing posture is denied unless explicitly allowed', () => {
  const decision = evaluatePolicy(basePolicy, facts({ posture: null }), FLOOR);
  assert.equal(decision.allow, false);
  assert.ok(decision.requirements.some((req) => req.name === 'posture'));
});

test('posture older than the rule limit is denied', () => {
  const policy = normalizePolicy(
    { version: 1, rules: [{ id: 'fresh', effect: 'allow', apps: ['wiki'], maxPostureAgeSeconds: 120 }] },
    FLOOR,
  );
  const stale = evaluatePolicy(
    policy,
    facts({
      now: new Date('2026-01-01T00:10:00Z'),
      posture: { ...facts().posture!, collectedAt: new Date('2026-01-01T00:00:00Z') },
    }),
    FLOOR,
  );
  assert.equal(stale.allow, false);
  assert.ok(stale.requirements.some((req) => req.name === 'postureFreshness' && !req.ok));
  const fresh = evaluatePolicy(policy, facts(), FLOOR);
  assert.equal(fresh.allow, true);
});

test('future-dated posture is rejected', () => {
  const decision = evaluatePolicy(
    basePolicy,
    facts({
      now: new Date('2026-01-01T00:00:00Z'),
      posture: { ...facts().posture!, collectedAt: new Date('2026-01-01T01:00:00Z') },
    }),
    FLOOR,
  );
  assert.equal(decision.allow, false);
});

test('first matching rule wins, so a deny rule above an allow rule carves out', () => {
  const policy = normalizePolicy(
    {
      version: 1,
      rules: [
        { id: 'block-contractors', effect: 'deny', apps: ['wiki'], groups: ['contractors'] },
        { id: 'allow-all-wiki', effect: 'allow', apps: ['wiki'] },
      ],
    },
    FLOOR,
  );
  const asContractor = evaluatePolicy(policy, facts({ group: 'contractors' }), FLOOR);
  assert.equal(asContractor.allow, false);
  assert.equal(asContractor.ruleId, 'block-contractors');
  const asEmployee = evaluatePolicy(policy, facts(), FLOOR);
  assert.equal(asEmployee.allow, true);
  assert.equal(asEmployee.ruleId, 'allow-all-wiki');
});

test('wildcard app rule applies to every application', () => {
  const policy = normalizePolicy(
    { version: 1, rules: [{ id: 'all', effect: 'allow', apps: ['*'], roles: ['employee'] }] },
    FLOOR,
  );
  assert.equal(evaluatePolicy(policy, facts({ appId: 'anything' }), FLOOR).allow, true);
});

test('per-OS minimums use the matching family, not a global string', () => {
  const policy = normalizePolicy(
    {
      version: 1,
      rules: [
        {
          id: 'versioned',
          effect: 'allow',
          apps: ['wiki'],
          minOsVersion: { macos: '14.2.0', windows: '10.0.19045' },
        },
      ],
    },
    FLOOR,
  );
  const macOk = evaluatePolicy(
    policy,
    facts({ posture: { ...facts().posture!, osName: 'macOS', osVersion: '14.6.1' } }),
    FLOOR,
  );
  assert.equal(macOk.allow, true);
  const macTooOld = evaluatePolicy(
    policy,
    facts({ posture: { ...facts().posture!, osName: 'macOS', osVersion: '14.1.0' } }),
    FLOOR,
  );
  assert.equal(macTooOld.allow, false);
  // Windows build numbers are orders of magnitude larger; comparing against a
  // macOS version would wrongly deny a patched Windows 11 machine.
  const windows = evaluatePolicy(
    policy,
    facts({ posture: { ...facts().posture!, osName: 'Windows', osVersion: '11.0.22631' } }),
    FLOOR,
  );
  assert.equal(windows.allow, true);
});

test('an OS family with no configured floor cannot be verified and fails closed', () => {
  const policy = normalizePolicy(
    {
      version: 1,
      rules: [
        { id: 'mac-only-floor', effect: 'allow', apps: ['wiki'], minOsVersion: { macos: '14.0.0' } },
      ],
    },
    FLOOR,
  );
  const decision = evaluatePolicy(
    policy,
    facts({ posture: { ...facts().posture!, osName: 'Ubuntu Linux', osVersion: '6.8.0' } }),
    FLOOR,
  );
  assert.equal(decision.allow, false);
  assert.ok(decision.requirements.some((req) => req.name === 'osVersion' && !req.ok));
});

test('osFamilies allow-list is enforced', () => {
  const policy = normalizePolicy(
    { version: 1, rules: [{ id: 'macs', effect: 'allow', apps: ['wiki'], osFamilies: ['macos'] }] },
    FLOOR,
  );
  assert.equal(evaluatePolicy(policy, facts(), FLOOR).allow, true);
  assert.equal(
    evaluatePolicy(policy, facts({ posture: { ...facts().posture!, osName: 'Windows' } }), FLOOR).allow,
    false,
  );
});

test('device groups and device ids constrain the rule', () => {
  const policy = normalizePolicy(
    {
      version: 1,
      rules: [
        { id: 'kiosk-only', effect: 'allow', apps: ['wiki'], deviceGroups: ['kiosk'] },
        { id: 'named', effect: 'allow', apps: ['wiki'], deviceIds: ['dev-blessed'] },
      ],
    },
    FLOOR,
  );
  assert.equal(evaluatePolicy(policy, facts(), FLOOR).allow, false);
  assert.equal(evaluatePolicy(policy, facts({ deviceGroup: 'kiosk' }), FLOOR).ruleId, 'kiosk-only');
  assert.equal(evaluatePolicy(policy, facts({ deviceId: 'dev-blessed' }), FLOOR).ruleId, 'named');
});

test('malformed policy is rejected rather than silently permissive', () => {
  assert.throws(() => normalizePolicy({ version: 1 }, FLOOR), PolicyError);
  assert.throws(() => normalizePolicy({ rules: [{ effect: 'allow', apps: [] }] }, FLOOR), PolicyError);
  assert.throws(() => normalizePolicy({ rules: [{ id: 'x', effect: 'maybe', apps: ['wiki'] }] }, FLOOR), PolicyError);
  assert.throws(
    () => normalizePolicy({ rules: [{ id: 'x', effect: 'allow', apps: ['wiki'], minOsVersion: 'latest' }] }, FLOOR),
    PolicyError,
  );
  assert.throws(
    () =>
      normalizePolicy(
        { rules: [{ id: 'x', effect: 'allow', apps: ['wiki'], minOsVersion: { solaris: '1.0' } }] },
        FLOOR,
      ),
    PolicyError,
  );
  assert.throws(
    () =>
      normalizePolicy(
        { rules: [{ id: 'dup', effect: 'allow', apps: ['wiki'] }, { id: 'dup', effect: 'deny', apps: ['wiki'] }] },
        FLOOR,
      ),
    PolicyError,
  );
});

test('requiresRevocation only fires on allow -> deny transitions', () => {
  const deny = evaluatePolicy(basePolicy, facts({ appId: 'nope' }), FLOOR);
  const allow = evaluatePolicy(basePolicy, facts(), FLOOR);
  assert.equal(requiresRevocation('allow', deny), true);
  assert.equal(requiresRevocation('allow', allow), false);
  assert.equal(requiresRevocation('deny', deny), false);
});
