import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLog } from '../src/audit.ts';

function tempFile(): { dir: string; file: string } {
  const dir = mkdtempSync(join(tmpdir(), 'zta-audit-'));
  return { dir, file: join(dir, 'audit.jsonl') };
}

test('audit records chain and verify', () => {
  const { dir, file } = tempFile();
  try {
    const log = new AuditLog({ filePath: file });
    log.record({ event: 'auth.login.success', outcome: 'allow', actor: { userId: 'alice' } });
    log.record({ event: 'access.allow', outcome: 'allow', actor: { userId: 'alice' }, appId: 'wiki' });
    log.record({ event: 'access.deny', outcome: 'deny', reasonCodes: ['posture.edr_stopped'] });
    const result = log.verifyChain();
    assert.deepEqual(result, { valid: true, entries: 3 });

    // Reload from disk: the chain must continue where it left off.
    const reloaded = new AuditLog({ filePath: file });
    const next = reloaded.record({ event: 'auth.logout', outcome: 'info' });
    assert.equal(next.seq, 4);
    assert.deepEqual(reloaded.verifyChain(), { valid: true, entries: 4 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('editing a record breaks the chain at that record', () => {
  const { dir, file } = tempFile();
  try {
    const audit = new AuditLog({ filePath: file });
    audit.record({ event: 'auth.login.success', outcome: 'allow', actor: { userId: 'alice' } });
    audit.record({ event: 'access.deny', outcome: 'deny', actor: { userId: 'alice' } });
    audit.record({ event: 'auth.logout', outcome: 'info', actor: { userId: 'alice' } });

    const lines = readFileSync(file, 'utf8').split('\n').filter(Boolean);
    const tampered = JSON.parse(lines[1]) as Record<string, unknown>;
    tampered.outcome = 'allow';
    lines[1] = JSON.stringify(tampered);
    writeFileSync(file, `${lines.join('\n')}\n`);

    const reopened = new AuditLog({ filePath: file });
    const result = reopened.verifyChain();
    assert.equal(result.valid, false);
    assert.equal(result.brokenAt, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('deleting a record is detected', () => {
  const { dir, file } = tempFile();
  try {
    const audit = new AuditLog({ filePath: file });
    for (let i = 0; i < 4; i += 1) {
      audit.record({ event: 'access.allow', outcome: 'allow', detail: { i } });
    }
    const lines = readFileSync(file, 'utf8').split('\n').filter(Boolean);
    lines.splice(2, 1);
    writeFileSync(file, `${lines.join('\n')}\n`);
    const result = new AuditLog({ filePath: file }).verifyChain();
    assert.equal(result.valid, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('recent() returns newest first and filters', () => {
  const audit = new AuditLog({ filePath: '' });
  audit.record({ event: 'access.allow', outcome: 'allow', appId: 'wiki' });
  audit.record({ event: 'access.deny', outcome: 'deny', appId: 'finance' });
  audit.record({ event: 'access.allow', outcome: 'allow', appId: 'wiki' });
  const recent = audit.recent(10);
  assert.equal(recent[0].seq, 3);
  assert.equal(audit.recent(10, { appId: 'finance' }).length, 1);
  assert.equal(audit.recent(10, { outcome: 'allow' }).length, 2);
});

test('secret values are truncated in the audit message', () => {
  const audit = new AuditLog({ filePath: '' });
  const entry = audit.record({ event: 'access.deny', outcome: 'deny', message: 'x'.repeat(1_000) });
  assert.ok((entry.message ?? '').length <= 501);
});
