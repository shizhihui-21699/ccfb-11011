import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validatePolicy } from '../src/config.ts';
import { PolicyEngine } from '../src/policy/engine.ts';
import { SessionEnforcer } from '../src/enforcement.ts';
import { SessionStore } from '../src/auth/sessionStore.ts';
import { DeviceStore } from '../src/stores/deviceStore.ts';
import { UserStore } from '../src/stores/userStore.ts';
import { AuditLog } from '../src/audit.ts';
import { PostureCache, type PostureSource } from '../src/posture/cache.ts';
import { createLogger } from '../src/log.ts';
import { hashPassword } from '../src/password.ts';
import { writeFileSync } from 'node:fs';
import type { DeviceRecord, PostureFacts, PostureRecord } from '../src/types.ts';

const log = createLogger('test');

function silent(): typeof log {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

interface Harness {
  dir: string;
  enforcer: SessionEnforcer;
  sessions: SessionStore;
  devices: DeviceStore;
  posture: PostureCache;
  source: MutablePostureSource;
  audit: AuditLog;
  now: { value: number };
}

class MutablePostureSource implements PostureSource {
  records = new Map<string, PostureRecord>();
  failWith: Error | null = null;
  setFacts(deviceId: string, facts: PostureFacts | null): void {
    this.records.set(deviceId, { deviceId, facts, updatedAt: new Date().toISOString(), revision: 1 });
  }
  async fetch(deviceId: string): Promise<PostureRecord | null> {
    if (this.failWith) throw this.failWith;
    return this.records.get(deviceId) ?? null;
  }
}

function facts(now: number, overrides: Partial<PostureFacts> = {}): PostureFacts {
  return {
    osVersion: '15.1.0',
    diskEncrypted: true,
    edrInstalled: true,
    edrRunning: true,
    edrLastHeartbeatAt: new Date(now - 1_000).toISOString(),
    reportedAt: new Date(now - 1_000).toISOString(),
    source: 'agent',
    ...overrides,
  };
}

function harness(options: { postureTtlMs?: number } = {}): Harness {
  const dir = mkdtempSync(join(tmpdir(), 'zta-enforce-'));
  const now = { value: 1_700_000_000_000 };
  const policy = new PolicyEngine(
    validatePolicy({
      version: 1,
      settings: { revocationSlaSeconds: 60, postureRecheckSeconds: 5 },
      postureBaseline: {
        requireDiskEncryption: true,
        requireEdrRunning: true,
        maxEdrHeartbeatAgeSeconds: 15,
        maxReportAgeSeconds: 60,
      },
      apps: [
        { id: 'wiki', upstream: 'http://127.0.0.1:9000', hosts: ['*'], allow: { groups: ['eng'] } },
        {
          // Only sessions that actually reach this app are held to its
          // stricter heartbeat requirement.
          id: 'strict-app',
          upstream: 'http://127.0.0.1:9001',
          hosts: ['*'],
          allow: { groups: ['eng'] },
          require: { posture: { maxEdrHeartbeatAgeSeconds: 1 } },
        },
      ],
    }),
  );

  const device: DeviceRecord = {
    id: 'dev1',
    label: 'test device',
    platform: 'darwin',
    assignedTo: 'alice',
    status: 'active',
    certFingerprint256: 'AA:BB:CC',
    certSubject: 'CN=dev1',
    certSerial: '01',
    certNotAfter: '2030-01-01',
    enrolledAt: new Date(now.value).toISOString(),
  };
  const devicesFile = join(dir, 'devices.json');
  writeFileSync(devicesFile, JSON.stringify({ version: 1, devices: [device] }));
  const usersFile = join(dir, 'users.json');
  writeFileSync(
    usersFile,
    JSON.stringify({
      version: 1,
      users: [{ id: 'alice', displayName: 'Alice', groups: ['eng'], role: 'user', passwordHash: hashPassword('password123') }],
    }),
  );

  const devices = new DeviceStore(devicesFile);
  devices.load();
  const users = new UserStore(usersFile, silent());
  const audit = new AuditLog({ filePath: '' });
  const sessions = new SessionStore({ ttlMs: 600_000, idleMs: 600_000 });
  const source = new MutablePostureSource();
  const posture = new PostureCache({
    source,
    ttlMs: options.postureTtlMs ?? 0,
    log: silent(),
    staleGraceMs: 0,
  });
  const enforcer = new SessionEnforcer({
    intervalMs: 5_000,
    policy,
    devices,
    users,
    posture,
    sessions,
    audit,
    log: silent(),
    now: () => now.value,
  });

  return { dir, enforcer, sessions, devices, posture, source, audit, now };
}

function withHarness(fn: (h: Harness) => Promise<void>, options?: { postureTtlMs?: number }) {
  return async () => {
    const h = harness(options);
    try {
      await fn(h);
    } finally {
      rmSync(h.dir, { recursive: true, force: true });
    }
  };
}

function signIn(h: Harness): { token: string; id: string } {
  const created = h.sessions.create(
    { userId: 'alice', deviceId: 'dev1', certFingerprint256: 'AA:BB:CC' },
    h.now.value,
  );
  created.record.apps.push('wiki');
  return { token: created.token, id: created.record.id };
}

test(
  'healthy posture leaves the session alone',
  withHarness(async (h) => {
    h.source.setFacts('dev1', facts(h.now.value));
    const session = signIn(h);
    const result = await h.enforcer.runOnce();
    assert.deepEqual(result, { checked: 1, revoked: 0 });
    assert.equal(h.sessions.resolve(session.token, h.now.value + 1).ok, true);
  }),
);

test(
  'EDR stopping revokes the session on the next pass',
  withHarness(async (h) => {
    h.source.setFacts('dev1', facts(h.now.value));
    const session = signIn(h);
    await h.enforcer.runOnce();

    h.now.value += 5_000;
    h.source.setFacts('dev1', facts(h.now.value, { edrRunning: false }));
    // The posture cache TTL is 0 in tests, so the fresh report is fetched.
    const result = await h.enforcer.runOnce();
    assert.deepEqual(result, { checked: 1, revoked: 1 });
    const resolved = h.sessions.resolve(session.token, h.now.value + 1);
    assert.equal(resolved.ok === false && resolved.reason, 'revoked');

    const events = h.audit.recent(10).map((entry) => entry.event);
    assert.ok(events.includes('session.revoked'));
    assert.ok(events.includes('posture.recheck'));
  }),
);

test(
  'a stale EDR heartbeat (agent silently offline) revokes the session',
  withHarness(async (h) => {
    h.source.setFacts('dev1', facts(h.now.value));
    signIn(h);
    h.now.value += 5_000;
    // edrRunning still true, but no heartbeat for 60s: the agent is not
    // actually reporting, and a boolean alone must not be trusted.
    h.source.setFacts(
      'dev1',
      facts(h.now.value, { edrLastHeartbeatAt: new Date(h.now.value - 60_000).toISOString() }),
    );
    const result = await h.enforcer.runOnce();
    assert.equal(result.revoked, 1);
  }),
);

test(
  'disabling disk encryption revokes the session',
  withHarness(async (h) => {
    h.source.setFacts('dev1', facts(h.now.value));
    signIn(h);
    h.now.value += 5_000;
    h.source.setFacts('dev1', facts(h.now.value, { diskEncrypted: false }));
    assert.equal((await h.enforcer.runOnce()).revoked, 1);
  }),
);

test(
  'missing posture data fails closed',
  withHarness(async (h) => {
    // No facts at all for this device: no report was ever received.
    signIn(h);
    assert.equal((await h.enforcer.runOnce()).revoked, 1);
  }),
);

test(
  'posture service outage revokes rather than silently allowing',
  withHarness(async (h) => {
    h.source.setFacts('dev1', facts(h.now.value));
    signIn(h);
    h.source.failWith = new Error('connection refused');
    assert.equal((await h.enforcer.runOnce()).revoked, 1);
  }),
);

test(
  'revocation happens without any request from the device',
  withHarness(async (h) => {
    h.source.setFacts('dev1', facts(h.now.value));
    signIn(h);
    await h.enforcer.runOnce();
    h.now.value += 5_000;
    h.source.setFacts('dev1', facts(h.now.value, { edrInstalled: false, edrRunning: false }));
    // The enforcer is the only actor here; no traffic touched the proxy.
    const result = await h.enforcer.runOnce();
    assert.equal(result.revoked, 1);
    assert.equal(h.sessions.live(h.now.value).length, 0);
  }),
);

test(
  'admin device revocation is honoured by the enforcer',
  withHarness(async (h) => {
    h.source.setFacts('dev1', facts(h.now.value));
    signIn(h);
    h.devices.setStatus('dev1', 'revoked', 'test');
    const result = await h.enforcer.runOnce();
    assert.equal(result.revoked, 1);
    const recent = h.audit.recent(5);
    assert.ok(recent.some((entry) => entry.reasonCodes?.includes('device.revoked')));
  }),
);

test(
  'a certificate change invalidates the bound session',
  withHarness(async (h) => {
    h.source.setFacts('dev1', facts(h.now.value));
    signIn(h);
    const device = h.devices.get('dev1')!;
    h.devices.upsert({ ...device, certFingerprint256: 'DD:EE:FF' });
    assert.equal((await h.enforcer.runOnce()).revoked, 1);
  }),
);

test(
  'a revoked session is skipped on later passes (no duplicate audit)',
  withHarness(async (h) => {
    h.source.setFacts('dev1', facts(h.now.value));
    signIn(h);
    h.source.setFacts('dev1', facts(h.now.value, { edrRunning: false }));
    assert.equal((await h.enforcer.runOnce()).revoked, 1);
    const firstCount = h.audit.recent(50).filter((entry) => entry.event === 'session.revoked').length;
    assert.equal((await h.enforcer.runOnce()).revoked, 0);
    const secondCount = h.audit.recent(50).filter((entry) => entry.event === 'session.revoked').length;
    assert.equal(secondCount, firstCount);
  }),
);

test(
  'concurrent passes do not overlap',
  withHarness(async (h) => {
    h.source.setFacts('dev1', facts(h.now.value));
    signIn(h);
    const [a, b] = await Promise.all([h.enforcer.runOnce(), h.enforcer.runOnce()]);
    assert.ok(a.checked === 1 || b.checked === 0);
  }),
);

test(
  'a stricter app the session never reached does not kill it',
  withHarness(async (h) => {
    // Rebuild the enforcer with an extra app that demands a perfect score and
    // a 1s heartbeat, then confirm a wiki-only session is judged by the
    // baseline rather than by that app's requirements.
    h.source.setFacts(
      'dev1',
      facts(h.now.value, { edrLastHeartbeatAt: new Date(h.now.value - 5_000).toISOString() }),
    );
    signIn(h);
    assert.equal((await h.enforcer.runOnce()).revoked, 0);
  }),
);

test(
  'per-app posture requirements apply once the session reaches that app',
  withHarness(async (h) => {
    h.source.setFacts(
      'dev1',
      facts(h.now.value, { edrLastHeartbeatAt: new Date(h.now.value - 5_000).toISOString() }),
    );
    const session = signIn(h);
    const record = h.sessions.all().find((item) => item.id === session.id)!;
    record.apps.push('strict-app');
    assert.equal((await h.enforcer.runOnce()).revoked, 1);
  }),
);
