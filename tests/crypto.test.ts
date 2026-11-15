import assert from 'node:assert/strict';
import { test } from 'node:test';
import { hashPassword, verifyPassword } from '../src/crypto/password.ts';
import { openSealed, seal } from '../src/crypto/seal.ts';

test('scrypt round-trips and rejects wrong passwords', async () => {
  const stored = await hashPassword('correct horse battery staple');
  assert.equal(await verifyPassword('correct horse battery staple', stored), true);
  assert.equal(await verifyPassword('correct horse battery staplE', stored), false);
});

test('each hash uses a fresh salt', async () => {
  const a = await hashPassword('same');
  const b = await hashPassword('same');
  assert.notEqual(a, b);
  assert.equal(await verifyPassword('same', a), true);
  assert.equal(await verifyPassword('same', b), true);
});

test('malformed stored hashes are rejected, not crashed on', async () => {
  for (const stored of ['', 'plain', 'scrypt$x$y$z$a$b', 'bcrypt$16384$8$1$aaaa$bbbb']) {
    assert.equal(await verifyPassword('anything', stored), false);
  }
});

test('sealed tokens round-trip with the right AAD', () => {
  const token = seal({ sid: 'sess_1', ttl: 60 }, 'secret-value', 'cookie', 60, 'dev-1:aa');
  const opened = openSealed(token.value, 'secret-value', 'cookie', 'dev-1:aa');
  assert.equal(opened?.sid, 'sess_1');
});

test('a sealed token does not open with different AAD (device binding)', () => {
  const token = seal({ sid: 'sess_1' }, 'secret-value', 'cookie', 60, 'dev-1:aa');
  assert.equal(openSealed(token.value, 'secret-value', 'cookie', 'dev-2:bb'), null);
});

test('a sealed token does not open with a different secret or purpose', () => {
  const token = seal({ sid: 'sess_1' }, 'secret-value', 'cookie', 60, 'dev-1:aa');
  assert.equal(openSealed(token.value, 'other-secret', 'cookie', 'dev-1:aa'), null);
  assert.equal(openSealed(token.value, 'secret-value', 'other-purpose', 'dev-1:aa'), null);
});

test('tampering with the ciphertext is detected', () => {
  const token = seal({ sid: 'sess_1' }, 'secret-value', 'cookie', 60, 'dev-1:aa');
  const raw = Buffer.from(token.value, 'base64url');
  const index = raw.length - 20;
  raw[index] = (raw[index] ?? 0) ^ 0xff;
  assert.equal(openSealed(raw.toString('base64url'), 'secret-value', 'cookie', 'dev-1:aa'), null);
});

test('expired tokens are refused', () => {
  const issued = Date.now() - 120_000;
  const token = seal({ sid: 'sess_1', ttl: 60 }, 'secret-value', 'cookie', 60, 'dev-1:aa', issued);
  assert.equal(openSealed(token.value, 'secret-value', 'cookie', 'dev-1:aa', Date.now()), null);
  assert.notEqual(openSealed(token.value, 'secret-value', 'cookie', 'dev-1:aa', issued + 30_000), null);
});

test('equal payloads still produce distinct ciphertexts (random IV)', () => {
  const a = seal({ sid: 'x', ttl: 60 }, 'secret', 'cookie', 60, 'aad');
  const b = seal({ sid: 'x', ttl: 60 }, 'secret', 'cookie', 60, 'aad');
  assert.notEqual(a.value, b.value);
});

