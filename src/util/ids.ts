import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

/** URL-safe random token with `bytes` of entropy (base64url, no padding). */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** Prefixed identifier, e.g. `sess_...`, safe for URLs and logs. */
export function newId(prefix: string): string {
  return `${prefix}_${randomUUID().replaceAll('-', '')}`;
}

/** Random positive integer serial rendered as lowercase hex, for X.509. */
export function randomSerial(): string {
  const bytes = randomBytes(16);
  // Keep it positive when interpreted as an ASN.1 integer.
  bytes[0] = (bytes[0]! & 0x7f) | 0x01;
  return bytes.toString('hex');
}

/** Constant-time comparison of two strings. Length is allowed to leak. */
export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
