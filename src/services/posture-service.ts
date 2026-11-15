/**
 * Simulated device posture service.
 *
 * In a real deployment the EDR/MDM vendor exposes this API and agents post
 * signed telemetry. Here it is a local HTTP service seeded from the PKI
 * manifest so the proxy has something to talk to. It also exposes a small
 * control surface used by the demo and tests:
 *
 *   GET  /v1/health                          → service status
 *   GET  /v1/posture/:deviceId               → current report (404 if none)
 *   GET  /v1/devices                         → all reports
 *   PUT  /v1/posture/:deviceId               → replace attributes (agent push)
 *   POST /v1/devices/:deviceId/state         → shorthand toggles for the demo
 *
 * The proxy additionally subscribes to `GET /v1/stream` (server-sent events)
 * to learn about changes immediately; the polling loop remains the fallback.
 */
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import type { AddressInfo } from 'node:net';

export interface PostureReport {
  deviceId: string;
  osName: string;
  osVersion: string;
  diskEncrypted: boolean;
  edrOnline: boolean;
  edrProduct: string;
  firewallEnabled: boolean;
  screenLockSeconds: number | null;
  patchLevel: string;
  /** ISO timestamp of when the endpoint agent collected the data. */
  collectedAt: string;
}

export interface ManifestDevice {
  id: string;
  /**
   * When true the simulator behaves like a live agent: `collectedAt` is bumped
   * on a timer. When false the report stays frozen (used to demo stale posture).
   */
  autoRefresh?: boolean;
  osName: string;
  osVersion: string;
  diskEncrypted: boolean;
  edrOnline: boolean;
  edrProduct: string;
  firewallEnabled: boolean;
  screenLockSeconds: number | null;
  patchLevel: string;
  postureAgeSeconds: number;
}

export interface PostureServiceOptions {
  /** Interval for simulated agent reports on autoRefresh devices. */
  refreshIntervalMs?: number;
  host?: string;
  port?: number;
  /** Seed from pki/devices.json when present. */
  manifestPath?: string;
  /** Extra reports supplied by tests. */
  seed?: PostureReport[];
  logger?: (event: string, detail: Record<string, unknown>) => void;
}

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8' } as const;

export function reportFromManifest(device: ManifestDevice, now = Date.now()): PostureReport {
  return {
    deviceId: device.id,
    osName: device.osName,
    osVersion: device.osVersion,
    diskEncrypted: device.diskEncrypted,
    edrOnline: device.edrOnline,
    edrProduct: device.edrProduct,
    firewallEnabled: device.firewallEnabled,
    screenLockSeconds: device.screenLockSeconds,
    patchLevel: device.patchLevel,
    collectedAt: new Date(now - device.postureAgeSeconds * 1000).toISOString(),
  };
}

export function loadManifest(manifestPath: string): ManifestDevice[] {
  if (!fs.existsSync(manifestPath)) return [];
  const parsed = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as { devices?: ManifestDevice[] };
  return Array.isArray(parsed.devices) ? parsed.devices : [];
}

export class PostureService {
  private readonly reports = new Map<string, PostureReport>();
  private readonly subscribers = new Set<http.ServerResponse>();
  private server: http.Server | null = null;
  private readonly host: string;
  private readonly port: number;
  private readonly logger: (event: string, detail: Record<string, unknown>) => void;
  private readonly autoRefreshIds = new Set<string>();
  private readonly refreshIntervalMs: number;
  private refreshTimer: NodeJS.Timeout | null = null;

  constructor(options: PostureServiceOptions = {}) {
    this.host = options.host ?? '127.0.0.1';
    this.port = options.port ?? 9200;
    this.logger = options.logger ?? (() => {});
    this.refreshIntervalMs = options.refreshIntervalMs ?? 30_000;
    if (options.manifestPath !== undefined) {
      for (const device of loadManifest(options.manifestPath)) {
        this.reports.set(device.id, reportFromManifest(device));
        if (device.autoRefresh === true) this.autoRefreshIds.add(device.id);
      }
    }
    for (const report of options.seed ?? []) {
      this.reports.set(report.deviceId, report);
    }
  }

  /** Current report for a device, or null when the device never reported. */
  get(deviceId: string): PostureReport | null {
    const report = this.reports.get(deviceId);
    return report ? structuredClone(report) : null;
  }

  list(): PostureReport[] {
    return [...this.reports.values()].map((report) => structuredClone(report));
  }

  /** Replaces a report wholesale and notifies subscribers. */
  put(report: PostureReport): void {
    this.reports.set(report.deviceId, structuredClone(report));
    this.broadcast({ type: 'posture', deviceId: report.deviceId });
    this.logger('posture.update', { deviceId: report.deviceId });
  }

  /** Applies a partial patch (used by the demo control surface). */
  patch(deviceId: string, changes: Partial<PostureReport>, refreshedAt = new Date()): PostureReport {
    const existing = this.reports.get(deviceId);
    const next: PostureReport = {
      ...(existing ?? {
        deviceId,
        osName: 'Unknown',
        osVersion: '0.0.0',
        diskEncrypted: false,
        edrOnline: false,
        edrProduct: 'none',
        firewallEnabled: false,
        screenLockSeconds: null,
        patchLevel: 'unknown',
        collectedAt: refreshedAt.toISOString(),
      }),
      ...changes,
      deviceId,
      // A report push always represents fresh collection unless the caller
      // supplies an explicit collection time.
      collectedAt: changes.collectedAt ?? refreshedAt.toISOString(),
    };
    this.put(next);
    return next;
  }

  /**
   * Simulated agent heartbeat: bumps `collectedAt` for autoRefresh devices so
   * healthy machines keep reporting, and broadcasts an SSE event (which the
   * proxy uses to re-evaluate immediately).
   */
  private refreshAgents(): void {
    for (const deviceId of this.autoRefreshIds) {
      const report = this.reports.get(deviceId);
      if (report === undefined) continue;
      report.collectedAt = new Date().toISOString();
      this.broadcast({ type: 'posture', deviceId });
    }
  }

  /** Starts the HTTP listener; resolves with the bound port. */
  async start(port = this.port): Promise<number> {
    if (this.server !== null) throw new Error('posture service already started');
    const server = http.createServer((req, res) => this.handle(req, res));
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, this.host, () => resolve());
    });
    if (this.autoRefreshIds.size > 0) {
      this.refreshTimer = setInterval(() => this.refreshAgents(), this.refreshIntervalMs);
      this.refreshTimer.unref();
    }
    return (server.address() as AddressInfo).port;
  }

  async stop(): Promise<void> {
    if (this.refreshTimer !== null) clearInterval(this.refreshTimer);
    this.refreshTimer = null;
    for (const subscriber of this.subscribers) subscriber.end();
    this.subscribers.clear();
    const server = this.server;
    this.server = null;
    if (server === null) return;
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }

  get address(): string {
    const server = this.server;
    if (server === null) return '';
    const address = server.address() as AddressInfo;
    return `http://${this.host}:${address.port}`;
  }

  private broadcast(event: Record<string, unknown>): void {
    const payload = `data: ${JSON.stringify(event)}\n\n`;
    for (const subscriber of this.subscribers) {
      try {
        subscriber.write(payload);
      } catch {
        this.subscribers.delete(subscriber);
      }
    }
  }

  private handle(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = new URL(req.url ?? '/', `http://${this.host}`);
    const method = req.method ?? 'GET';
    try {
      if (method === 'GET' && (url.pathname === '/' || url.pathname === '/v1/health')) {
        return this.send(res, 200, { status: 'ok', devices: this.reports.size, time: new Date().toISOString() });
      }
      if (method === 'GET' && url.pathname === '/v1/devices') {
        return this.send(res, 200, { devices: this.list() });
      }
      if (method === 'GET' && url.pathname === '/v1/stream') {
        res.writeHead(200, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-cache',
          connection: 'keep-alive',
        });
        res.write(': connected\n\n');
        this.subscribers.add(res);
        req.on('close', () => this.subscribers.delete(res));
        return;
      }
      const postureMatch = /^\/v1\/posture\/([A-Za-z0-9._-]+)$/.exec(url.pathname);
      if (postureMatch) {
        const deviceId = postureMatch[1]!;
        if (method === 'GET') {
          const report = this.get(deviceId);
          if (report === null) {
            return this.send(res, 404, { error: 'no posture for device', deviceId });
          }
          return this.send(res, 200, report);
        }
        if (method === 'PUT' || method === 'POST') {
          return this.readJson(req, (body) => {
            if (body === null) return this.send(res, 400, { error: 'invalid JSON body' });
            const updated = this.patch(deviceId, sanitizeReportPatch(body));
            return this.send(res, 200, updated);
          });
        }
        return this.send(res, 405, { error: 'method not allowed' });
      }
      const stateMatch = /^\/v1\/devices\/([A-Za-z0-9._-]+)\/state$/.exec(url.pathname);
      if (stateMatch && method === 'POST') {
        const deviceId = stateMatch[1]!;
        return this.readJson(req, (body) => {
          if (body === null) return this.send(res, 400, { error: 'invalid JSON body' });
          const patch = sanitizeStateToggles(body);
          const updated = this.patch(deviceId, patch);
          return this.send(res, 200, updated);
        });
      }
      return this.send(res, 404, { error: 'not found', path: url.pathname });
    } catch (error) {
      this.send(res, 500, { error: error instanceof Error ? error.message : String(error) });
    }
  }

  private readJson(
    req: http.IncomingMessage,
    handler: (body: Record<string, unknown> | null) => void,
  ): void {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 256 * 1024) {
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (text.trim() === '') return handler({});
      try {
        const parsed = JSON.parse(text) as unknown;
        handler(parsed !== null && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null);
      } catch {
        handler(null);
      }
    });
  }

  private send(res: http.ServerResponse, status: number, body: unknown): void {
    const payload = JSON.stringify(body, null, 2);
    res.writeHead(status, { ...JSON_HEADERS, 'content-length': Buffer.byteLength(payload) });
    res.end(payload);
  }
}

function booleanField(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['true', 'on', 'yes', '1', 'enabled'].includes(normalized)) return true;
    if (['false', 'off', 'no', '0', 'disabled'].includes(normalized)) return false;
  }
  if (value === 1) return true;
  if (value === 0) return false;
  return undefined;
}

function sanitizeReportPatch(body: Record<string, unknown>): Partial<PostureReport> {
  const patch: Partial<PostureReport> = {};
  if (typeof body.osName === 'string') patch.osName = body.osName.slice(0, 64);
  if (typeof body.osVersion === 'string') patch.osVersion = body.osVersion.slice(0, 32);
  if (typeof body.edrProduct === 'string') patch.edrProduct = body.edrProduct.slice(0, 64);
  if (typeof body.patchLevel === 'string') patch.patchLevel = body.patchLevel.slice(0, 32);
  for (const key of ['diskEncrypted', 'edrOnline', 'firewallEnabled'] as const) {
    const parsed = booleanField(body[key]);
    if (parsed !== undefined) patch[key] = parsed;
  }
  if (body.screenLockSeconds === null) {
    patch.screenLockSeconds = null;
  } else if (typeof body.screenLockSeconds === 'number' && body.screenLockSeconds >= 0) {
    patch.screenLockSeconds = Math.floor(body.screenLockSeconds);
  }
  if (typeof body.collectedAt === 'string') {
    const at = new Date(body.collectedAt);
    if (!Number.isNaN(at.getTime())) patch.collectedAt = at.toISOString();
  }
  return patch;
}

/** Maps demo-friendly toggles (`edr: "off"`) onto report fields. */
function sanitizeStateToggles(body: Record<string, unknown>): Partial<PostureReport> {
  const patch: Partial<PostureReport> = {};
  const edr = booleanField(body.edr) ?? booleanField(body.edrOnline);
  if (edr !== undefined) patch.edrOnline = edr;
  const disk = booleanField(body.diskEncrypted) ?? booleanField(body.encryption);
  if (disk !== undefined) patch.diskEncrypted = disk;
  const firewall = booleanField(body.firewall) ?? booleanField(body.firewallEnabled);
  if (firewall !== undefined) patch.firewallEnabled = firewall;
  if (typeof body.osVersion === 'string') patch.osVersion = body.osVersion.slice(0, 32);
  if (body.refresh === true) patch.collectedAt = new Date().toISOString();
  if (typeof body.refresh === 'string' && body.refresh === 'backdate') {
    patch.collectedAt = new Date(Date.now() - 30 * 60 * 1000).toISOString();
  }
  return patch;
}

/** Resolves the manifest path used to seed the simulator. */
export function defaultManifestPath(pkiDir: string): string {
  return path.join(pkiDir, 'devices.json');
}
