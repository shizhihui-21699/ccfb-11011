import assert from 'node:assert/strict';
import { test } from 'node:test';
import { openDatabase } from '../src/store/db.ts';
import { AuditLog } from '../src/store/audit.ts';

function freshLog(): { log: AuditLog; db: ReturnType<typeof openDatabase> } {
  const db = openDatabase(':memory:');
  return { log: new AuditLog(db, 'test-audit-secret'), db };
}

test('appends records and verifies the chain', () => {
  const { log } = freshLog();
  for (let index = 0; index < 5; index += 1) {
    log.append({
      actorType: 'user',
      actorId: 'usr_1',
      action: 'app.access',
      decision: 'allow',
      reason: `request ${index}`,
      appId: 'wiki',
    });
  }
  const verification = log.verify();
  assert.equal(verification.ok, true);
  assert.equal(verification.records, 5);
  assert.equal(log.count(), 5);
});

test('chain detects a modified record', () => {
  const { log, db } = freshLog();
  for (let index = 0; index < 3; index += 1) {
    log.append({ actorType: 'system', actorId: 'sys', action: 'tick', decision: 'info', reason: `t${index}` });
  }
  db.prepare("UPDATE audit SET reason = 'tampered' WHERE id = 2").run();
  const verification = log.verify();
  assert.equal(verification.ok, false);
  assert.equal(verification.brokenAt, 2);
});

test('chain detects a deleted record', () => {
  const { log, db } = freshLog();
  for (let index = 0; index < 4; index += 1) {
    log.append({ actorType: 'system', actorId: 'sys', action: 'tick', decision: 'info', reason: `t${index}` });
  }
  db.prepare('DELETE FROM audit WHERE id = 2').run();
  const verification = log.verify();
  assert.equal(verification.ok, false);
  assert.equal(verification.brokenAt, 3);
});

test('anchors are written every 64 records and validated', () => {
  const { log, db } = freshLog();
  for (let index = 0; index < 130; index += 1) {
    log.append({ actorType: 'system', actorId: 'sys', action: 'tick', decision: 'info', reason: `t${index}` });
  }
  const verification = log.verify();
  assert.equal(verification.ok, true);
  assert.equal(verification.records, 130);
  assert.equal(verification.anchors, 2);

  // Rewriting an anchored head must be detected even with a valid chain.
  db.prepare('UPDATE audit_anchors SET mac = ? WHERE audit_id = 64').run('0'.repeat(64));
  const tampered = log.verify();
  assert.equal(tampered.ok, false);
  assert.equal(tampered.brokenAt, 64);
});

test('a different secret cannot validate existing anchors', () => {
  const { log, db } = freshLog();
  for (let index = 0; index < 64; index += 1) {
    log.append({ actorType: 'system', actorId: 'sys', action: 'tick', decision: 'info', reason: `t${index}` });
  }
  assert.equal(log.verify().ok, true);
  const foreignLog = new AuditLog(db, 'a-different-secret');
  assert.equal(foreignLog.verify().ok, false);
});

test('recent() filters by device and decision', () => {
  const { log } = freshLog();
  log.append({
    actorType: 'device',
    actorId: 'dev-a',
    action: 'app.access',
    decision: 'allow',
    reason: 'ok',
    deviceId: 'dev-a',
  });
  log.append({
    actorType: 'device',
    actorId: 'dev-b',
    action: 'app.access',
    decision: 'deny',
    reason: 'no',
    deviceId: 'dev-b',
  });
  assert.equal(log.recent(10, { deviceId: 'dev-a' }).length, 1);
  assert.equal(log.recent(10, { decision: 'deny' }).length, 1);
  assert.equal(log.recent(10).length, 2);
});

test('JSONL export round-trips every field', () => {
  const { log } = freshLog();
  log.append({
    actorType: 'user',
    actorId: 'usr_9',
    action: 'auth.login',
    decision: 'allow',
    reason: 'ok',
    detail: { nested: { a: 1 } },
  });
  const line = log.toJsonl().split('\n')[0]!;
  const parsed = JSON.parse(line) as Record<string, unknown>;
  assert.equal(parsed.actorId, 'usr_9');
  assert.deepEqual(parsed.detail, { nested: { a: 1 } });
  assert.equal(typeof parsed.hash, 'string');
});
