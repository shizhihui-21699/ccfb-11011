/**
 * Streaming reverse proxy to an upstream application.
 *
 * The proxy owns identity: it strips any inbound X-ZTA-* / Forwarded headers
 * and sets its own, so an upstream can trust them.
 */
import { request as httpRequest, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { AppPolicy, DeviceRecord, PostureEvaluation } from '../types.ts';
import { clientIp } from './httpUtil.ts';
import type { Logger } from '../log.ts';

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
]);

const RESERVED_PREFIX = /^x-zta-/i;

export interface ProxyContext {
  app: AppPolicy;
  user: { id: string; displayName: string; groups: string[] };
  device: DeviceRecord;
  posture: PostureEvaluation;
  sessionId: string;
  requestId: string;
  /** The decoded path the policy matched (not the raw request target). */
  path: string;
  log: Logger;
  timeoutMs: number;
}

export function proxyRequest(req: IncomingMessage, res: ServerResponse, context: ProxyContext): Promise<void> {
  const upstream = new URL(context.app.upstream);
  const basePath = upstream.pathname.replace(/\/$/, '');
  const incomingUrl = new URL(req.url ?? '/', 'http://placeholder');
  // Forward the decoded path the policy matched, re-encoded per segment.
  // Reusing the raw request target would let an upstream that decodes
  // differently see path segments the policy never evaluated.
  const encodedPath = context.path
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
  const targetPath = `${basePath}${encodedPath}`.replace(/\/{2,}/g, '/');
  const target = `${targetPath}${incomingUrl.search}`;

  const headers: IncomingHttpHeaders = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    if (HOP_BY_HOP.has(key.toLowerCase())) continue;
    if (RESERVED_PREFIX.test(key)) continue;
    headers[key] = value;
  }
  headers.host = upstream.host;
  // Never leak the proxy session cookie upstream.
  if (headers.cookie) {
    const remaining = stripCookie(headers.cookie, ['__Host-zta_session', '__Host-zta_csrf']);
    if (remaining) headers.cookie = remaining;
    else delete headers.cookie;
  }

  const ip = clientIp(req);
  const forwardedFor = [req.headers['x-forwarded-for'], ip].filter(Boolean).join(', ');
  headers['x-forwarded-for'] = forwardedFor;
  headers['x-forwarded-proto'] = 'https';
  headers['x-forwarded-host'] = req.headers.host ?? '';
  headers['x-request-id'] = context.requestId;

  headers['x-zta-user'] = context.user.id;
  headers['x-zta-user-name'] = headerSafe(context.user.displayName);
  headers['x-zta-groups'] = context.user.groups.map(headerSafe).join(',');
  headers['x-zta-device'] = context.device.id;
  headers['x-zta-device-platform'] = context.device.platform;
  headers['x-zta-posture'] = context.posture.status;
  headers['x-zta-posture-score'] = String(context.posture.score);
  headers['x-zta-app'] = context.app.id;
  headers['x-zta-session'] = context.sessionId;

  for (const [key, value] of Object.entries(context.app.injectHeaders ?? {})) {
    headers[key.toLowerCase()] = value;
  }

  const isHttps = upstream.protocol === 'https:';
  const transport = isHttps ? httpsRequest : httpRequest;
  const options = {
    protocol: upstream.protocol,
    hostname: upstream.hostname,
    port: upstream.port || (isHttps ? 443 : 80),
    method: req.method,
    path: target,
    headers,
    timeout: context.timeoutMs,
  };

  return new Promise<void>((resolve) => {
    const upstreamReq = transport(options, (upstreamRes) => {
      const responseHeaders: Record<string, string | string[]> = {};
      for (const [key, value] of Object.entries(upstreamRes.headers)) {
        if (value === undefined) continue;
        if (HOP_BY_HOP.has(key.toLowerCase())) continue;
        responseHeaders[key] = value;
      }
      // Upstreams must never set cookies scoped to a proxy path we also use.
      const setCookie = upstreamRes.headers['set-cookie'];
      if (setCookie) {
        responseHeaders['set-cookie'] = setCookie.map((cookie) =>
          cookie.replace(/;\s*domain=[^;]*/gi, '').replace(/;\s*secure/gi, '; Secure'),
        );
      }
      res.writeHead(upstreamRes.statusCode ?? 502, responseHeaders);
      upstreamRes.pipe(res);
      upstreamRes.on('end', resolve);
      upstreamRes.on('error', (error) => {
        context.log.warn('upstream response error', { appId: context.app.id, error: error.message });
        res.destroy();
        resolve();
      });
    });

    upstreamReq.on('timeout', () => {
      context.log.warn('upstream timeout', { appId: context.app.id, requestId: context.requestId });
      upstreamReq.destroy(new Error('upstream timeout'));
    });
    upstreamReq.on('error', (error) => {
      context.log.error('upstream request failed', { appId: context.app.id, error: error.message });
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
        res.end('Upstream application is unavailable.\n');
      } else {
        res.destroy();
      }
      resolve();
    });

    // Do not forward a body for methods that cannot have one.
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
      upstreamReq.end();
    } else {
      req.pipe(upstreamReq);
      req.on('error', () => upstreamReq.destroy());
    }
  });
}

function stripCookie(header: string, names: string[]): string | undefined {  const kept = header
    .split(';')
    .map((part) => part.trim())
    .filter((part) => {
      const key = part.slice(0, part.indexOf('=')).trim();
      return !names.includes(key);
    });
  return kept.length > 0 ? kept.join('; ') : undefined;
}

/**
 * Strip characters that cannot appear in an HTTP header value. Names come
 * from the directory, which is external input even when it is normally clean;
 * encoding rather than silently dropping keeps the value unambiguous.
 */
function headerSafe(value: string): string {
  return value.replace(/[^\x20-\x7e]/g, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
