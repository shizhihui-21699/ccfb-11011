import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

export function sha256Base64Url(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('base64url');
}

export function hmacHex(secret: string | Buffer, input: string): string {
  return createHmac('sha256', secret).update(input).digest('hex');
}

export function hmacBase64Url(secret: string | Buffer, input: string): string {
  return createHmac('sha256', secret).update(input).digest('base64url');
}

export function verifyHmac(
  secret: string | Buffer,
  input: string,
  expectedHex: string,
): boolean {
  const expected = Buffer.from(expectedHex, 'hex');
  if (expected.length !== 32) return false;
  const actual = createHmac('sha256', secret).update(input).digest();
  return timingSafeEqual(actual, expected);
}

/**
 * Deterministic JSON with sorted object keys, used for audit hashes and
 * signatures so that semantically equal payloads hash identically.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) sorted[key] = sortValue(record[key]);
    return sorted;
  }
  return value;
}
