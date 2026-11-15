import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SessionStore } from '../src/auth/sessionStore.ts';
import { RateLimiter } from '../src/auth/rateLimit.ts';

const TTL = { ttlMs: 60_000, idleMs: 10_000 };

function store(): SessionStore {
  return new SessionStore(TTL);
}

test('a fresh session resolves and refreshes idle time', () => {
  const sessions = store();
  const { token, record } = sessions.create({ userId: 'alice', deviceId: 'dev1', certFingerprint256: 'aa' }, 1_000);
  const resolved = sessions.resolve(token, 5_000);
  assert.equal(resolved.ok, true);
  assert.equal(resolved.ok && resolved.record.userId, 'alice');
  assert.equal(record.lastSeenAt, 5_000);
  // Idle timer was refreshed by the successful resolve above: 14s after
  // creation but only 9s idle, so this still resolves.
  assert.equal(sessions.resolve(token, 14_000).ok, true);
  assert.equal(record.lastSeenAt, 14_000);
});

test('tokens are not stored in plaintext', () => {
  const sessions = store();
  const { token } = sessions.create({ userId: 'alice', deviceId: 'dev1', certFingerprint256: 'aa' }, 0);
  assert.ok(!JSON.stringify(sessions.all()).includes(token));
});

test('expired and idle sessions stop resolving', () => {
  const sessions = store();
  const { token } = sessions.create({ userId: 'alice', deviceId: 'dev1', certFingerprint256: 'aa' }, 0);
  const idle = sessions.resolve(token, 10_001);
  assert.equal(idle.ok, false);
  assert.equal(idle.ok === false && idle.reason, 'idle');

  const sessions2 = store();
  const created = sessions2.create({ userId: 'alice', deviceId: 'dev1', certFingerprint256: 'aa' }, 0);
  const expired = sessions2.resolve(created.token, 60_000);
  assert.equal(expired.ok === false && expired.reason, 'expired');
});

test('revocation is immediate and fires the hook once', () => {
  const sessions = store();
  let calls = 0;
  sessions.onRevoke = () => {
    calls += 1;
  };
  const { token, record } = sessions.create({ userId: 'alice', deviceId: 'dev1', certFingerprint256: 'aa' }, 0);
  sessions.revokeRecord(record, 'posture', [{ code: 'posture.edr_stopped', message: 'EDR stopped' }], 100);
  sessions.revokeRecord(record, 'posture', undefined, 200);
  assert.equal(calls, 1);
  const resolved = sessions.resolve(token, 300);
  assert.equal(resolved.ok === false && resolved.reason, 'revoked');
});

test('revokeForDevice only touches that device', () => {
  const sessions = store();
  const a = sessions.create({ userId: 'a', deviceId: 'dev1', certFingerprint256: 'aa' }, 0);
  const b = sessions.create({ userId: 'b', deviceId: 'dev2', certFingerprint256: 'bb' }, 0);
  const revoked = sessions.revokeForDevice('dev1', 'admin', 10);
  assert.equal(revoked.length, 1);
  assert.equal(sessions.resolve(a.token, 20).ok, false);
  assert.equal(sessions.resolve(b.token, 20).ok, true);
});

test('live() excludes revoked, expired and idle sessions', () => {
  const sessions = store();
  sessions.create({ userId: 'a', deviceId: 'd1', certFingerprint256: 'aa' }, 0);
  const revoked = sessions.create({ userId: 'b', deviceId: 'd2', certFingerprint256: 'bb' }, 0);
  sessions.revokeRecord(revoked.record, 'test', undefined, 1);
  sessions.create({ userId: 'c', deviceId: 'd3', certFingerprint256: 'cc' }, 0);
  // At t=50s everything is idle (lastSeen 0, idle limit 10s).
  assert.equal(sessions.live(50_000).length, 0);
  assert.equal(sessions.live(5_000).length, 2);
});

test('rate limiter locks out after the configured failures', () => {
  const limiter = new RateLimiter({ maxFailures: 3, windowSeconds: 60, lockoutSeconds: 120 });
  assert.equal(limiter.check('alice', 0).allowed, true);
  limiter.recordFailure('alice', 1_000);
  limiter.recordFailure('alice', 2_000);
  assert.equal(limiter.check('alice', 3_000).allowed, true);
  limiter.recordFailure('alice', 4_000);
  const locked = limiter.check('alice', 5_000);
  assert.equal(locked.allowed, false);
  assert.ok((locked.retryAfterSeconds ?? 0) > 0);
  // Other keys are unaffected.
  assert.equal(limiter.check('bob', 5_000).allowed, true);
  // Lockout runs from the last failure (t=4s) for 120s.
  assert.equal(limiter.check('alice', 123_999).allowed, false);
  assert.equal(limiter.check('alice', 124_000).allowed, true);
});

test('rate limiter failure window resets', () => {
  const limiter = new RateLimiter({ maxFailures: 3, windowSeconds: 10, lockoutSeconds: 60 });
  limiter.recordFailure('alice', 0);
  limiter.recordFailure('alice', 1_000);
  limiter.recordFailure('alice', 2_000);
  const locked = limiter.check('alice', 3_000);
  assert.equal(locked.allowed, false);
  // Lockout runs from the last failure (t=2000) for 60s.
  assert.equal(limiter.check('alice', 61_999).allowed, false);
  assert.equal(limiter.check('alice', 62_000).allowed, true);
  // After the lockout the counter starts over.
  limiter.recordFailure('alice', 62_001);
  assert.equal(limiter.check('alice', 62_002).allowed, true);
});

test('recordSuccess clears failures', () => {
  const limiter = new RateLimiter({ maxFailures: 2, windowSeconds: 60, lockoutSeconds: 60 });
  limiter.recordFailure('alice', 0);
  limiter.recordSuccess('alice');
  limiter.recordFailure('alice', 1);
  assert.equal(limiter.check('alice', 2).allowed, true);
});

test('reapExpired reports each ended session exactly once', () => {
  const sessions = store();
  const expired = sessions.create({ userId: 'a', deviceId: 'd1', certFingerprint256: 'aa' }, 0);
  const idle = sessions.create({ userId: 'b', deviceId: 'd2', certFingerprint256: 'bb' }, 0);
  const live = sessions.create({ userId: 'c', deviceId: 'd3', certFingerprint256: 'cc' }, 0);
  // Keep the third session alive: resolve every 5s (idle limit is 10s).
  for (let t = 5_000; t < 59_000; t += 5_000) {
    assert.equal(sessions.resolve(live.token, t).ok, true);
  }

  // Just before the third session's hard TTL, only the first two have ended.
  const reaped = sessions.reapExpired(59_999);
  const ids = reaped.map((record) => record.id).sort();
  assert.deepEqual(ids, [expired.record.id, idle.record.id].sort());
  assert.deepEqual(sessions.reapExpired(59_999), []);
});
