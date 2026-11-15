/**
 * Small HTTP helpers: cookie parsing, response sending, body reading, and the
 * security headers applied to every response.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';

export interface CookieAttributes {
  maxAgeSeconds?: number;
  path?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
}

export function parseCookies(header: string | undefined): Map<string, string> {
  const cookies = new Map<string, string>();
  if (header === undefined) return cookies;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name === '') continue;
    try {
      cookies.set(name, decodeURIComponent(value));
    } catch {
      cookies.set(name, value);
    }
  }
  return cookies;
}

export function serializeCookie(name: string, value: string, attributes: CookieAttributes = {}): string {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${attributes.path ?? '/'}`);
  const maxAge = attributes.maxAgeSeconds;
  if (maxAge !== undefined) {
    parts.push(`Max-Age=${maxAge}`);
    parts.push(`Expires=${new Date(Date.now() + maxAge * 1000).toUTCString()}`);
  }
  if (attributes.httpOnly ?? true) parts.push('HttpOnly');
  if (attributes.secure ?? true) parts.push('Secure');
  parts.push(`SameSite=${attributes.sameSite ?? 'Lax'}`);
  return parts.join('; ');
}

export function clearCookie(name: string, path = '/'): string {
  return `${name}=; Path=${path}; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

export function setSecurityHeaders(res: ServerResponse, nonce?: string): void {
  const scriptSources = nonce === undefined ? "'self'" : `'nonce-${nonce}'`;
  res.setHeader(
    'content-security-policy',
    [
      "default-src 'self'",
      `script-src ${scriptSources}`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'self'",
    ].join('; '),
  );
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('cache-control', 'no-store');
}

export function sendHtml(res: ServerResponse, status: number, html: string, nonce?: string): void {
  setSecurityHeaders(res, nonce);
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(html);
}

export function sendJson(res: ServerResponse, status: number, body: unknown): void {
  setSecurityHeaders(res);
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

export function sendText(res: ServerResponse, status: number, body: string, contentType = 'text/plain; charset=utf-8'): void {
  setSecurityHeaders(res);
  res.writeHead(status, { 'content-type': contentType });
  res.end(body);
}

export function redirect(res: ServerResponse, location: string, status = 303): void {
  res.writeHead(status, { location, 'cache-control': 'no-store' });
  res.end();
}

export function readBody(req: IncomingMessage, limit = 64 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        reject(new HttpError(413, 'request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export function parseForm(body: Buffer): URLSearchParams {
  return new URLSearchParams(body.toString('utf8'));
}

export class HttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * The remote address, honoring X-Forwarded-For only when explicitly trusted.
 */
export function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = req.headers['x-forwarded-for'];
    const value = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    if (typeof value === 'string' && value.trim() !== '') {
      return value.split(',')[0]!.trim();
    }
  }
  return req.socket.remoteAddress ?? 'unknown';
}

/** Escapes text for safe inclusion in HTML. */
export function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/** Escapes a value for inclusion inside a JS string in a <script> block. */
export function escapeJs(value: string): string {
  return value.replaceAll('\\', '\\\\').replaceAll('</', '<\\/').replaceAll("'", "\\'");
}
