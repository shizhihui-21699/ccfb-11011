/**
 * Small sealed-token helpers. Session cookies are AES-256-GCM encrypted and
 * bound to the connection's device id as additional authenticated data, so a
 * cookie copied to another device's TLS connection fails to open.
 *
 * The session secret is stretched with SHA-256 so any sufficiently long input
 * works; production deployments should supply a 32-byte base64 value.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  createHash,
  randomBytes,
} from 'node:crypto';
import { safeEqual } from '../util/ids.ts';

export interface SealedToken {
  /** base64url(iv || ciphertext || tag) */
  value: string;
  expiresAt: number;
}

const IV_LENGTH = 12;

function deriveKey(secret: string, purpose: string): Buffer {
  return createHash('sha256').update(`${purpose}:${secret}`).digest();
}

export function seal(
  payload: Record<string, unknown>,
  secret: string,
  purpose: string,
  ttlSeconds: number,
  aad: string,
  now = Date.now(),
): SealedToken {
  const key = deriveKey(secret, purpose);
  const iv = randomBytes(IV_LENGTH);
  const body = JSON.stringify({ ...payload, iat: now });
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(body, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    value: Buffer.concat([iv, ciphertext, tag]).toString('base64url'),
    expiresAt: now + ttlSeconds * 1000,
  };
}

/** Returns the payload, or null for tampering, wrong AAD, or expiry. */
export function openSealed(
  token: string,
  secret: string,
  purpose: string,
  aad: string,
  now = Date.now(),
): Record<string, unknown> | null {
  const raw = Buffer.from(token, 'base64url');
  if (raw.length <= IV_LENGTH + 16) return null;
  const iv = raw.subarray(0, IV_LENGTH);
  const tag = raw.subarray(raw.length - 16);
  const ciphertext = raw.subarray(IV_LENGTH, raw.length - 16);
  let body: string;
  try {
    const decipher = createDecipheriv('aes-256-gcm', deriveKey(secret, purpose), iv);
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    body = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object') return null;
  const record = parsed as Record<string, unknown>;
  const issuedAt = record.iat;
  if (typeof issuedAt !== 'number' || !Number.isFinite(issuedAt)) return null;
  const ttl = record.ttl;
  if (typeof ttl === 'number' && now > issuedAt + ttl * 1000) return null;
  return record;
}

/** Deterministic opaque handle for a nonce/csrf value. */
export function deriveHandle(secret: string, value: string): string {
  return createHmac('sha256', secret).update(value).digest('base64url').slice(0, 22);
}

export function handlesEqual(a: string, b: string): boolean {
  return a.length === b.length && safeEqual(a, b);
}
