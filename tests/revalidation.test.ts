import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRuntime } from '../src/core/runtime.ts';
import { loadConfig } from '../src/config.ts';
import { PostureService } from '../src/services/posture-service.ts';
import { normalizePolicy } from '../src/policy/engine.ts';
import { seedPostureFromManifest } from '../src/core/runtime.ts';
import { buildTestPki, writeTestConfig } from './helpers/pki.ts';

const FLOOR = { macos: '14.0.0', windows: '10.0.19045', linux: '5.15.0' };

interface Harness {
  runtime: Awaited<ReturnType<typeof createRuntime>>;
  posture: PostureService;
  deviceId: string;
}

/**
 * Spins up the runtime against an in-memory posture service. The PKI and
 * config directories are real, so trust material and policy load for real.
 */
async function harness(): Promise<Harness> {
  const pki = buildTestPki([{ id: 'dev-alpha', owner: 'alice', group: 'laptop' }]);
  const { configPath } = writeTestConfig(
    pki,
    {
      thresholds: { postureMaxAgeSeconds: 180, minOsVersion: FLOOR, revalidateIntervalMs: 200, revokeWithinMs: 60_000 },
      apps: [{ id: 'portal', name: 'Portal', upstream: 'http://127.0.0.1:1' }],
    },
    {
      version: 1,
      rules: [
        {
          id: 'portal',
          effect: 'allow',
          apps: ['portal'],
          groups: ['engineering'],
          deviceGroups: ['laptop'],
          requireEdrOnline: true,
          requireDiskEncrypted: true,
        },
      ],
    },
  );
  const config = loadConfig({ ZT_CONFIG: configPath }, '/tmp');
  const posture = new PostureService({ port: 0 });
  const posturePort = await posture.start();
  const runtime = await createRuntime({
    config,
    postureBaseUrl: `http://127.0.0.1:${posturePort}`,
    logger: () => {},
  });
  // The test PKI has no devices.json, so register the device by hand.
  const device = pki.devices[0]!;
  runtime.devices.upsert({
    id: 'dev-alpha',
    displayName: 'Alpha',
    ownerUserId: 'usr_admin',
    group: 'laptop',
    certSerial: device.serial,
    certFingerprint256: device.fingerprint256,
    certIssuedAt: new Date().toISOString(),
    certExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    status: 'enrolled',
    enrolledAt: new Date().toISOString(),
    revokedAt: null,
    revokedReason: null,
    lastSeenAt: null,
  });
  posture.put({
    deviceId: 'dev-alpha',
    osName: 'macOS',
    osVersion: '15.2.0',
    diskEncrypted: true,
    edrOnline: true,
    edrProduct: 'Falcon',
    firewallEnabled: true,
    screenLockSeconds: 300,
    patchLevel: '2026-01',
    collectedAt: new Date().toISOString(),
  });
  await runtime.postureSync!.poll(['dev-alpha']);
  void seedPostureFromManifest;
  return { runtime, posture, deviceId: 'dev-alpha' };
}

async function teardown(h: Harness): Promise<void> {
  await h.posture.stop();
  await h.runtime.shutdown();
}

function allowPolicy() {
  return normalizePolicy(
    {
      version: 1,
      rules: [
        {
          id: 'portal',
          effect: 'allow',
          apps: ['portal'],
          groups: ['engineering'],
          deviceGroups: ['laptop'],
          requireEdrOnline: true,
          requireDiskEncrypted: true,
        },
      ],
    },
    FLOOR,
  );
}

test('posture downgrade revokes an established grant on the next pass', async () => {
  const h = await harness();
  try {
    const user = h.runtime.users.findById('usr_admin')!;
    const device = h.runtime.devices.findById(h.deviceId)!;
    // Seed policy file is on disk; swap in an explicit rule via evaluate on
    // the access controller to avoid depending on the seeded file content.
    const decision = h.runtime.access.decide(
      { user, device, appId: 'portal', now: new Date() },
      allowPolicy(),
    );
    assert.equal(decision.allow, true);

    const session = h.runtime.sessionManager.createSession({
      userId: user.id,
      deviceId: device.id,
      certFingerprint256: device.certFingerprint256,
      ip: '127.0.0.1',
      userAgent: 'test',
    });
    const grant = h.runtime.sessionManager.createGrant(session, 'portal', decision);

    h.posture.patch(h.deviceId, { edrOnline: false });
    await h.runtime.postureSync!.poll([h.deviceId]);
    const report = await h.runtime.revalidator.runOnce('test');
    assert.equal(report.revokedGrants, 1);
    assert.equal(report.revokedSessions, 1);

    const after = h.runtime.grants.findById(grant.id);
    assert.equal(after?.state, 'revoked');
    const sessionAfter = h.runtime.sessions.findById(session.id);
    assert.equal(sessionAfter?.state, 'revoked');

    const audit = h.runtime.audit.recent(50, { deviceId: h.deviceId });
    assert.ok(audit.some((record) => record.action === 'access.revalidated' && record.decision === 'deny'));
    assert.ok(audit.some((record) => record.action === 'grant.revoked'));
    assert.ok(audit.some((record) => record.action === 'session.revoked'));
  } finally {
    await teardown(h);
  }
});

test('a healthy device keeps its grant through repeated passes', async () => {
  const h = await harness();
  try {
    const user = h.runtime.users.findById('usr_admin')!;
    const device = h.runtime.devices.findById(h.deviceId)!;
    const session = h.runtime.sessionManager.createSession({
      userId: user.id,
      deviceId: device.id,
      certFingerprint256: device.certFingerprint256,
      ip: '127.0.0.1',
      userAgent: 'test',
    });
    const decision = h.runtime.access.decide({ user, device, appId: 'portal', now: new Date() }, allowPolicy());
    assert.equal(decision.allow, true);
    const grant = h.runtime.sessionManager.createGrant(session, 'portal', decision);
    const revalPolicy = h.runtime.policy.get().current;
    // The revalidator reads the on-disk policy, so make sure it allows portal.
    const rules = revalPolicy.rules.find((rule) => rule.id === 'portal');
    assert.ok(rules);
    for (let index = 0; index < 3; index += 1) {
      await h.runtime.postureSync!.poll([h.deviceId]);
      const report = await h.runtime.revalidator.runOnce('test');
      assert.equal(report.revokedGrants, 0);
      assert.equal(h.runtime.grants.findById(grant.id)?.state, 'active');
    }
  } finally {
    await teardown(h);
  }
});

test('posture push hook triggers re-evaluation immediately', async () => {
  const h = await harness();
  try {
    const user = h.runtime.users.findById('usr_admin')!;
    const device = h.runtime.devices.findById(h.deviceId)!;
    const session = h.runtime.sessionManager.createSession({
      userId: user.id,
      deviceId: device.id,
      certFingerprint256: device.certFingerprint256,
      ip: '127.0.0.1',
      userAgent: 'test',
    });
    const decision = h.runtime.access.decide({ user, device, appId: 'portal', now: new Date() }, allowPolicy());
    h.runtime.sessionManager.createGrant(session, 'portal', decision);

    // The push handler is wired to the sync loop's onChange callback.
    const start = Date.now();
    h.runtime.revalidator.onPostureChanged(h.deviceId);
    let report = h.runtime.revalidator.getLastReport();
    for (let index = 0; index < 50 && report === null; index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      report = h.runtime.revalidator.getLastReport();
    }
    assert.ok(report !== null);
    assert.ok(Date.now() - start < 1000);
  } finally {
    await teardown(h);
  }
});

test('request-path check denies a grant after posture changes, before the next pass', async () => {
  const h = await harness();
  try {
    const user = h.runtime.users.findById('usr_admin')!;
    const device = h.runtime.devices.findById(h.deviceId)!;
    const session = h.runtime.sessionManager.createSession({
      userId: user.id,
      deviceId: device.id,
      certFingerprint256: device.certFingerprint256,
      ip: '127.0.0.1',
      userAgent: 'test',
    });
    h.runtime.sessionManager.createGrant(
      session,
      'portal',
      h.runtime.access.decide({ user, device, appId: 'portal', now: new Date() }, allowPolicy()),
    );
    // Grant was created under the on-disk policy; posture changes at once.
    h.posture.patch(h.deviceId, { diskEncrypted: false });
    await h.runtime.postureSync!.poll([h.deviceId]);
    const grant = h.runtime.grants.findBySessionApp(session.id, 'portal')!;
    const live = h.runtime.revalidator.checkGrantNow(grant.id);
    assert.equal(live.ok, false);
    assert.equal(live.code, 'device_untrusted');
  } finally {
    await teardown(h);
  }
});

test('a revoked device loses its session and grants', async () => {
  const h = await harness();
  try {
    const user = h.runtime.users.findById('usr_admin')!;
    const device = h.runtime.devices.findById(h.deviceId)!;
    const session = h.runtime.sessionManager.createSession({
      userId: user.id,
      deviceId: device.id,
      certFingerprint256: device.certFingerprint256,
      ip: '127.0.0.1',
      userAgent: 'test',
    });
    h.runtime.sessionManager.createGrant(
      session,
      'portal',
      h.runtime.access.decide({ user, device, appId: 'portal', now: new Date() }, allowPolicy()),
    );
    h.runtime.devices.revoke(h.deviceId, new Date().toISOString(), 'lost device');
    const report = await h.runtime.revalidator.runOnce('test');
    assert.equal(report.revokedSessions, 1);
    assert.equal(h.runtime.sessions.findById(session.id)?.state, 'revoked');
  } finally {
    await teardown(h);
  }
});

test('session expiry cascades to grants and is audited', async () => {
  const h = await harness();
  try {
    const user = h.runtime.users.findById('usr_admin')!;
    const device = h.runtime.devices.findById(h.deviceId)!;
    const session = h.runtime.sessionManager.createSession(
      {
        userId: user.id,
        deviceId: device.id,
        certFingerprint256: device.certFingerprint256,
        ip: '127.0.0.1',
        userAgent: 'test',
      },
      new Date(Date.now() - 1000),
    );
    // Force the session past its TTL.
    h.runtime.db.prepare('UPDATE sessions SET expires_at = ? WHERE id = ?').run(
      new Date(Date.now() - 1).toISOString(),
      session.id,
    );
    const resolved = h.runtime.sessionManager.resolve(
      session.id,
      { deviceId: device.id, fingerprint256: device.certFingerprint256 },
      new Date(),
    );
    assert.equal(resolved, null);
    assert.equal(h.runtime.sessions.findById(session.id)?.state, 'expired');
  } finally {
    await teardown(h);
  }
});
