/**
 * Local posture reporting service.
 *
 * In a real deployment this is the EDR/MDM integration endpoint. Here it is a
 * separate HTTP service that receives reports from (simulated) device agents
 * and lets the access proxy pull the latest posture with a service token.
 *
 * Security properties:
 *  - agents authenticate with a per-device token; the token is bound to the
 *    device id, so one agent cannot report for another device
 *  - the proxy's read token is separate from agent tokens
 *  - payloads are validated and size-capped
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Platform, PostureFacts } from './types.ts';
import { createLogger } from './log.ts';
import { PostureStore } from './posture/store.ts';
import { nowIso, safeEqual } from './util.ts';
import { parseJsonBody, readBody, sendJson } from './http/httpUtil.ts';

const ROOT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const log = createLogger('posture-service');

interface AgentTokenFile {
  version: 1;
  tokens: Record<string, string>;
}

function loadAgentTokens(): Map<string, string> {
  const path = resolve(process.env.ZTA_AGENT_TOKENS_FILE ?? join(ROOT_DIR, 'data', 'agent-tokens.json'));
  if (!existsSync(path)) {
    throw new Error(`agent token file missing: ${path} (run "npm run setup")`);
  }
  const raw = JSON.parse(readFileSync(path, 'utf8')) as AgentTokenFile;
  if (raw.version !== 1 || typeof raw.tokens !== 'object') throw new Error(`${path}: unsupported format`);
  const byDevice = new Map<string, string>();
  for (const [deviceId, token] of Object.entries(raw.tokens)) byDevice.set(deviceId, token);
  return byDevice;
}

function serviceToken(): string {
  const inline = process.env.ZTA_POSTURE_TOKEN;
  if (inline) return inline;
  const path = resolve(process.env.ZTA_POSTURE_TOKEN_FILE ?? join(ROOT_DIR, 'data', 'posture-token.txt'));
  try {
    return readFileSync(path, 'utf8').trim();
  } catch {
    throw new Error(`posture service token missing (${path}); run "npm run setup"`);
  }
}

const PLATFORMS: Platform[] = ['darwin', 'win32', 'linux'];

function isIsoDate(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

/** Strict validation: reject anything we would not want the proxy to act on. */
export function validateReport(input: unknown, now = Date.now()): { deviceId: string; facts: PostureFacts } {
  if (typeof input !== 'object' || input === null) throw new Error('report must be an object');
  const body = input as Record<string, unknown>;
  const deviceId = body.deviceId;
  if (typeof deviceId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/.test(deviceId)) {
    throw new Error('invalid deviceId');
  }
  const platform = body.platform;
  if (typeof platform !== 'string' || !PLATFORMS.includes(platform as Platform)) {
    throw new Error(`platform must be one of ${PLATFORMS.join(', ')}`);
  }
  const osVersion = body.osVersion;
  if (typeof osVersion !== 'string' || osVersion.length > 64 || !osVersion.trim()) {
    throw new Error('invalid osVersion');
  }
  for (const key of ['diskEncrypted', 'edrInstalled', 'edrRunning'] as const) {
    if (typeof body[key] !== 'boolean') throw new Error(`${key} must be a boolean`);
  }
  if (!isIsoDate(body.reportedAt)) throw new Error('reportedAt must be an ISO timestamp');
  if (body.edrLastHeartbeatAt !== null && body.edrLastHeartbeatAt !== undefined && !isIsoDate(body.edrLastHeartbeatAt)) {
    throw new Error('edrLastHeartbeatAt must be an ISO timestamp or null');
  }
  if (body.osBuild !== undefined && (typeof body.osBuild !== 'string' || body.osBuild.length > 64)) {
    throw new Error('invalid osBuild');
  }
  if (body.agentVersion !== undefined && (typeof body.agentVersion !== 'string' || body.agentVersion.length > 64)) {
    throw new Error('invalid agentVersion');
  }

  // Never trust the reporter's clock for freshness. `reportedAt` is stamped by
  // this service on receipt, so a lying (or badly-skewed) agent cannot make an
  // old report look new. The EDR heartbeat is agent-supplied, so it is clamped
  // to "no later than now" for the same reason.
  const claimedHeartbeat = typeof body.edrLastHeartbeatAt === 'string' ? Date.parse(body.edrLastHeartbeatAt) : null;
  const heartbeatAt =
    claimedHeartbeat === null ? null : new Date(Math.min(claimedHeartbeat, now)).toISOString();

  const facts: PostureFacts = {
    osVersion: osVersion.trim(),
    osBuild: typeof body.osBuild === 'string' ? body.osBuild : undefined,
    diskEncrypted: body.diskEncrypted === true,
    edrInstalled: body.edrInstalled === true,
    edrRunning: body.edrRunning === true,
    edrLastHeartbeatAt: heartbeatAt,
    agentVersion: typeof body.agentVersion === 'string' ? body.agentVersion : undefined,
    reportedAt: new Date(now).toISOString(),
    source: body.source === 'simulator' ? 'simulator' : 'agent',
  };
  return { deviceId, facts };
}

function bearer(req: IncomingMessage): string {
  const header = req.headers.authorization ?? '';
  return header.startsWith('Bearer ') ? header.slice(7).trim() : '';
}

function agentToken(req: IncomingMessage): string {
  const header = req.headers['x-agent-token'];
  if (typeof header === 'string' && header) return header.trim();
  return bearer(req);
}

export interface PostureServiceOptions {
  host?: string;
  port?: number;
  dataFile?: string;
  agentTokens?: Map<string, string>;
  readToken?: string;
}

export function createPostureService(options: PostureServiceOptions = {}) {
  const store = new PostureStore(
    resolve(options.dataFile ?? process.env.ZTA_POSTURE_DATA ?? join(ROOT_DIR, 'data', 'posture.json')),
  );
  const tokens = options.agentTokens ?? loadAgentTokens();
  const readToken = options.readToken ?? serviceToken();

  const server = createServer((req, res) => {
    handle(req, res).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : 'internal error';
      if (!res.headersSent) sendJson(res, 500, { error: 'internal_error', message });
      else res.destroy();
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://posture.local');
    const path = url.pathname;

    if (path === '/healthz') {
      sendJson(res, 200, { ok: true, service: 'posture', time: nowIso() });
      return;
    }

    if (path === '/v1/report' && req.method === 'POST') {
      const token = agentToken(req);
      if (!token) {
        sendJson(res, 401, { error: 'unauthorized', message: 'agent token required' });
        return;
      }
      let body: Buffer;
      try {
        body = await readBody(req, 16 * 1024);
      } catch {
        sendJson(res, 413, { error: 'payload_too_large' });
        return;
      }
      let report: { deviceId: string; facts: PostureFacts };
      try {
        report = validateReport(parseJsonBody(body));
      } catch (error) {
        sendJson(res, 400, { error: 'invalid_report', message: (error as Error).message });
        return;
      }
      const expected = tokens.get(report.deviceId);
      if (!expected || !safeEqual(expected, token)) {
        log.warn('agent token rejected', { deviceId: report.deviceId });
        sendJson(res, 403, { error: 'forbidden', message: 'token does not authorize this device' });
        return;
      }
      const record = store.upsert(report.deviceId, report.facts);
      log.info('posture report accepted', {
        deviceId: report.deviceId,
        revision: record.revision,
        diskEncrypted: report.facts.diskEncrypted,
        edrRunning: report.facts.edrRunning,
      });
      sendJson(res, 202, { accepted: true, revision: record.revision, recordedAt: record.updatedAt });
      return;
    }

    if (path.startsWith('/v1/posture') && req.method === 'GET') {
      if (!safeEqual(bearer(req), readToken)) {
        sendJson(res, 401, { error: 'unauthorized' });
        return;
      }
      if (path === '/v1/posture') {
        sendJson(res, 200, { records: store.list() });
        return;
      }
      const match = /^\/v1\/posture\/([^/]+)$/.exec(path);
      if (!match) {
        sendJson(res, 404, { error: 'not_found' });
        return;
      }
      const record = store.get(decodeURIComponent(match[1]));
      if (!record) {
        sendJson(res, 404, { error: 'not_found', message: 'no posture report for this device' });
        return;
      }
      sendJson(res, 200, { record });
      return;
    }

    sendJson(res, 404, { error: 'not_found' });
  }

  return {
    server,
    store,
    listen(host = options.host ?? process.env.ZTA_POSTURE_HOST ?? '127.0.0.1', port = options.port ?? 8450): Promise<number> {
      return new Promise((resolvePort, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.off('error', reject);
          const address = server.address();
          resolvePort(typeof address === 'object' && address ? address.port : port);
        });
      });
    },
    close(): Promise<void> {
      store.close();
      return new Promise((resolveClose) => server.close(() => resolveClose()));
    },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const service = createPostureService();
  const port = await service.listen();
  log.info('posture service listening', { port });
  const shutdown = () => {
    log.info('shutting down posture service');
    void service.close().then(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
