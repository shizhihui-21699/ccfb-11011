import { createHash, randomBytes } from 'node:crypto';

export function nowIso(now = Date.now()): string {
  return new Date(now).toISOString();
}

/** Stable JSON encoding (sorted keys, recursively) used for audit hashes. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      if (obj[key] !== undefined) out[key] = sortValue(obj[key]);
    }
    return out;
  }
  return value;
}

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function randomId(prefix: string, bytes = 8): string {
  return `${prefix}_${randomBytes(bytes).toString('hex')}`;
}

export function secondsBetween(laterMs: number, earlierMs: number): number {
  return Math.floor((laterMs - earlierMs) / 1000);
}

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/** Parse the leading dotted numeric portion of a version string. */
export function parseVersion(version: string): number[] | null {
  const match = /^\s*v?(\d+(?:\.\d+)*)/.exec(version);
  if (!match) return null;
  const parts = match[1].split('.').map((n) => Number.parseInt(n, 10));
  return parts.every((n) => Number.isFinite(n)) ? parts : null;
}

/** Compares numeric version parts; missing parts count as zero. */
export function compareVersions(a: string, b: string): number | null {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return null;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const l = left[i] ?? 0;
    const r = right[i] ?? 0;
    if (l !== r) return l < r ? -1 : 1;
  }
  return 0;
}

/** Normalizes Host header values: lowercase, strip port, strip trailing dot. */
export function normalizeHost(host: string | undefined): string {
  if (!host) return '';
  const trimmed = host.trim().toLowerCase();
  const withoutPort = trimmed.startsWith('[')
    ? trimmed.replace(/^(\[[^\]]+\])(?::\d+)?$/, '$1')
    : trimmed.replace(/:\d+$/, '');
  return withoutPort.replace(/\.$/, '');
}

export function matchesHostPattern(host: string, pattern: string): boolean {
  const normalized = normalizeHost(pattern);
  if (!normalized) return false;
  const candidate = host.trim().toLowerCase();
  if (!normalized.includes('*')) return candidate === normalized;
  const escaped = normalized
    .split('*')
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
    .join('[^.]*');
  return new RegExp(`^${escaped}$`, 'i').test(candidate);
}

/** Prefix match on path segment boundaries: /foo matches /foo/bar but not /foobar. */
export function matchesPathPrefix(pathname: string, prefix: string): boolean {
  const p = prefix.startsWith('/') ? prefix : `/${prefix}`;
  if (p === '/') return true;
  const clean = p.endsWith('/') ? p.slice(0, -1) : p;
  return pathname === clean || pathname.startsWith(`${clean}/`);
}

export function sanitizeNextPath(next: string | null | undefined): string {
  if (!next || !next.startsWith('/') || next.startsWith('//')) return '/';
  if (next.includes('\\') || next.includes('\r') || next.includes('\n')) return '/';
  return next;
}

/**
 * Resolve a request path for policy matching.
 *
 * The URL parser normalizes literal `..` segments, but an encoded `%2E%2E%2F`
 * survives as text and can be decoded by an upstream into a path the policy
 * never matched. Since a prefix policy is only as strong as path agreement
 * between proxy and upstream, encoded slashes, encoded dots and control
 * characters are rejected outright.
 */
export function resolveRequestPath(rawPath: string): { ok: true; path: string } | { ok: false; reason: string } {
  if (/%(2f|5c)/i.test(rawPath)) return { ok: false, reason: 'encoded path separator' };
  if (/%(2e|00|0a|0d)/i.test(rawPath)) return { ok: false, reason: 'encoded dot or control character' };
  let decoded: string;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    return { ok: false, reason: 'malformed percent-encoding' };
  }
  if (decoded.includes('\\') || decoded.includes('\0')) return { ok: false, reason: 'illegal character in path' };
  if (/[\x00-\x1f\x7f]/.test(decoded)) return { ok: false, reason: 'control character in path' };
  // A still-escaped sequence after one decode means the request is double
  // encoded; an upstream that decodes twice would see a different path.
  if (/%[0-9a-f]{2}/i.test(decoded)) return { ok: false, reason: 'double-encoded path' };
  // Defense in depth: the URL parser should already have collapsed these.
  const segments = decoded.split('/');
  if (segments.some((segment) => segment === '..' || segment === '.')) {
    return { ok: false, reason: 'dot segment in path' };
  }
  return { ok: true, path: decoded };
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(value);
    } catch {
      out[key] = value;
    }
  }
  return out;
}

/** Constant-time-ish comparison for secret strings of equal length. */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function truncate(value: string, max = 200): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}

/** Remove duplicated denial reasons, keeping the first occurrence of each code. */
export function dedupeReasons<T extends { code: string }>(reasons: T[]): T[] {
  const seen = new Set<string>();
  return reasons.filter((reason) => {
    if (seen.has(reason.code)) return false;
    seen.add(reason.code);
    return true;
  });
}
