import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  AccessController,
  evaluateBaseline,
} from '../src/core/access.ts';
import { openDatabase } from '../src/store/db.ts';
import { DeviceStore, PostureStore, UserStore } from '../src/store/repositories.ts';
import type { Config } from '../src/config.ts';
import { normalizePolicy } from '../src/policy/engine.ts';

const FLOOR = { macos: '14.0.0', windows: '10.0.19045', linux: '5.15.0' };

function makeConfig(overrides: Partial<Config['thresholds']> = {}): Config {
  return {
    host: '127.0.0.1',
    port: 0,
    publicOrigin: 'https://test',
    pkiDir: '/tmp/none',
    configDir: '/tmp/none',
    dbPath: ':memory:',
    sessionSecret: 'x'.repeat(32),
    sessionTtlSeconds: 3600,
    grantTtlSeconds: 3600,
    thresholds: {
      postureMaxAgeSeconds: 180,
      minOsVersion: FLOOR,
      revalidateIntervalMs: 1000,
      revokeWithinMs: 60_000,
      ...overrides,
    },
    apps: [],
    seedUsers: [],
    postureService: { host: '127.0.0.1', port: 0 },
    trustProxy: false,
  };
}

function setup(now = new Date('2026-01-01T00:00:30Z')) {
  const db = openDatabase(':memory:');
  const users = new UserStore(db);
  const devices = new DeviceStore(db);
  const posture = new PostureStore(db);
  const config = makeConfig();
  users.insert({
    id: 'usr_1',
    username: 'alice',
    displayName: 'Alice',
    passwordHash: 'hash',
    roles: ['employee'],
    group: 'engineering',
    disabled: false,
    createdAt: now.toISOString(),
  });
  devices.upsert({
    id: 'dev_1',
    displayName: 'Laptop',
    ownerUserId: 'usr_1',
    group: 'laptop',
    certSerial: '01',
    certFingerprint256: 'aa',
    certIssuedAt: now.toISOString(),
    certExpiresAt: new Date(now.getTime() + 86_400_000).toISOString(),
    status: 'enrolled',
    enrolledAt: now.toISOString(),
    revokedAt: null,
    revokedReason: null,
    lastSeenAt: null,
  });
  posture.upsert({
    deviceId: 'dev_1',
    osName: 'macOS',
    osVersion: '15.2.0',
    diskEncrypted: true,
    edrOnline: true,
    edrProduct: 'Falcon',
    firewallEnabled: true,
    screenLockSeconds: 300,
    patchLevel: '2026-01',
    collectedAt: new Date(now.getTime() - 30_000).toISOString(),
    receivedAt: now.toISOString(),
    source: 'agent',
    reportedBy: 'test',
  });
  return { db, users, devices, posture, config, now };
}

const policy = normalizePolicy(
  {
    version: 1,
    rules: [{ id: 'allow-wiki', effect: 'allow', apps: ['wiki'], roles: ['employee'] }],
  },
  FLOOR,
);

test('baseline passes for fresh, encrypted, EDR-online posture', () => {
  const env = setup();
  const result = evaluateBaseline(env.posture.get('dev_1'), env.config, env.now);
  assert.equal(result.ok, true);
  assert.equal(result.requirements.length, 3);
});

test('baseline fails closed with no posture', () => {
  const env = setup();
  const result = evaluateBaseline(null, env.config, env.now);
  assert.equal(result.ok, false);
  assert.equal(result.code, 'posture_missing');
});

test('baseline fails on stale posture', () => {
  const env = setup();
  const stale = { ...env.posture.get('dev_1')!, collectedAt: new Date(env.now.getTime() - 200_000).toISOString() };
  const result = evaluateBaseline(stale, env.config, env.now);
  assert.equal(result.ok, false);
  assert.equal(result.code, 'posture_stale');
});

test('baseline fails on unencrypted disk and offline EDR', () => {
  const env = setup();
  for (const patch of [{ diskEncrypted: false }, { edrOnline: false }]) {
    const result = evaluateBaseline({ ...env.posture.get('dev_1')!, ...patch }, env.config, env.now);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'device_untrusted');
  }
});

test('full decision allows a healthy device', () => {
  const env = setup();
  const access = new AccessController({ users: env.users, devices: env.devices, posture: env.posture, config: env.config });
  const decision = access.decide(
    { user: env.users.findById('usr_1')!, device: env.devices.findById('dev_1')!, appId: 'wiki', now: env.now },
    policy,
  );
  assert.equal(decision.allow, true);
  assert.equal(decision.ruleId, 'allow-wiki');
});

test('device revocation is a device-wide trust failure', () => {
  const env = setup();
  env.devices.revoke('dev_1', env.now.toISOString(), 'stolen');
  const access = new AccessController({ users: env.users, devices: env.devices, posture: env.posture, config: env.config });
  const decision = access.decide(
    { user: env.users.findById('usr_1')!, device: env.devices.findById('dev_1')!, appId: 'wiki', now: env.now },
    policy,
  );
  assert.equal(decision.allow, false);
  assert.equal(decision.code, 'device_revoked');
  assert.equal(decision.deviceTrustFailure, true);
});

test('a disabled account is denied without a device-wide signal', () => {
  const env = setup();
  env.users.setDisabled('usr_1', true);
  const access = new AccessController({ users: env.users, devices: env.devices, posture: env.posture, config: env.config });
  const decision = access.decide(
    { user: env.users.findById('usr_1')!, device: env.devices.findById('dev_1')!, appId: 'wiki', now: env.now },
    policy,
  );
  assert.equal(decision.allow, false);
  assert.equal(decision.code, 'user_disabled');
  assert.equal(decision.deviceTrustFailure, false);
});

test('certificate bound to a different owner cannot be used by another user', () => {
  const env = setup();
  env.users.insert({
    id: 'usr_2',
    username: 'bob',
    displayName: 'Bob',
    passwordHash: 'hash2',
    roles: ['employee'],
    group: 'engineering',
    disabled: false,
    createdAt: env.now.toISOString(),
  });
  const access = new AccessController({ users: env.users, devices: env.devices, posture: env.posture, config: env.config });
  const decision = access.decide(
    { user: env.users.findById('usr_2')!, device: env.devices.findById('dev_1')!, appId: 'wiki', now: env.now },
    policy,
  );
  assert.equal(decision.allow, false);
  assert.equal(decision.code, 'device_owner_mismatch');
  assert.equal(decision.deviceTrustFailure, true);
});

test('device baseline cannot be relaxed by policy allowMissingPosture', () => {
  const env = setup();
  const laxPolicy = normalizePolicy(
    { version: 1, rules: [{ id: 'lax', effect: 'allow', apps: ['wiki'], allowMissingPosture: true }] },
    FLOOR,
  );
  const access = new AccessController({ users: env.users, devices: env.devices, posture: env.posture, config: env.config });
  const decision = access.decide(
    {
      user: env.users.findById('usr_1')!,
      device: env.devices.findById('dev_1')!,
      appId: 'wiki',
      now: env.now,
      posture: null,
    },
    laxPolicy,
  );
  assert.equal(decision.allow, false);
  assert.equal(decision.code, 'posture_missing');
});

test('revalidate fails closed when the user row disappears', () => {
  const env = setup();
  const access = new AccessController({ users: env.users, devices: env.devices, posture: env.posture, config: env.config });
  const decision = access.revalidate({ userId: 'usr_missing', deviceId: 'dev_1', appId: 'wiki' }, policy, env.now);
  assert.equal(decision.allow, false);
  assert.equal(decision.code, 'user_missing');
});
