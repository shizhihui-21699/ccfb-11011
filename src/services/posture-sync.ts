/**
 * HTTP client + synchronization layer for the posture service.
 *
 * Two things happen here:
 *   1. A background poll refreshes every enrolled device's cached posture.
 *   2. A subscription to the service's SSE stream turns a posture change into
 *      an immediate re-evaluation, so the revocation SLA does not depend on
 *      the poll interval alone.
 *
 * Failures never delete cached posture; instead the snapshot ages, and the
 * policy engine fails closed once it exceeds `postureMaxAgeSeconds`.
 */
import type { PostureSnapshotRecord } from '../store/types.ts';
import { PostureStore } from '../store/repositories.ts';
import type { PostureReport } from './posture-service.ts';

export interface PostureSyncOptions {
  baseUrl: string;
  store: PostureStore;
  pollIntervalMs: number;
  /** Called after any snapshot is written (poll or push). */
  onChange?: (deviceId: string) => void;
  fetchImpl?: typeof fetch;
  logger?: (event: string, detail: Record<string, unknown>) => void;
}

export interface SyncStatus {
  lastPollAt: Date | null;
  lastPollError: string | null;
  lastPushAt: Date | null;
  streamConnected: boolean;
  pollCount: number;
  reportCount: number;
}

export class PostureSync {
  private readonly baseUrl: string;
  private readonly store: PostureStore;
  private readonly pollIntervalMs: number;
  private readonly onChange: ((deviceId: string) => void) | undefined;
  private readonly fetchImpl: typeof fetch;
  private readonly logger: (event: string, detail: Record<string, unknown>) => void;
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private controller: AbortController | null = null;
  private status: SyncStatus = {
    lastPollAt: null,
    lastPollError: null,
    lastPushAt: null,
    streamConnected: false,
    pollCount: 0,
    reportCount: 0,
  };

  constructor(options: PostureSyncOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.store = options.store;
    this.pollIntervalMs = options.pollIntervalMs;
    this.onChange = options.onChange;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.logger = options.logger ?? (() => {});
  }

  getStatus(): SyncStatus {
    return { ...this.status };
  }

  /**
   * Fetches posture for the given devices and writes snapshots. Devices that
   * 404 keep their previous snapshot (which then ages out). Resolves with the
   * number of snapshots written.
   */
  async refresh(deviceIds: string[], receivedAt = new Date()): Promise<number> {
    let written = 0;
    for (const deviceId of deviceIds) {
      const report = await this.fetchReport(deviceId);
      if (report === null) continue;
      this.writeSnapshot(report, deviceId, receivedAt);
      written += 1;
    }
    return written;
  }

  /** Single-device fetch, used right after login and by the checks. */
  async fetchReport(deviceId: string): Promise<PostureReport | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}/v1/posture/${encodeURIComponent(deviceId)}`, {
        signal: controller.signal,
        headers: { accept: 'application/json' },
      });
      if (response.status === 404) return null;
      if (!response.ok) throw new Error(`posture service returned ${response.status}`);
      return (await response.json()) as PostureReport;
    } catch (error) {
      this.status.lastPollError = error instanceof Error ? error.message : String(error);
      this.logger('posture.fetch_failed', { deviceId, error: this.status.lastPollError });
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * One polling cycle over the supplied device ids. Used both by the timer and
   * directly by tests.
   */
  async poll(deviceIds: string[]): Promise<number> {
    const receivedAt = new Date();
    const written = await this.refresh(deviceIds, receivedAt);
    this.status.lastPollAt = receivedAt;
    this.status.pollCount += 1;
    this.status.reportCount = this.store.list().length;
    if (written > 0) this.status.lastPollError = null;
    return written;
  }

  /** Starts the polling timer and opens the SSE subscription. */
  start(deviceIdProvider: () => string[]): void {
    if (this.running) return;
    this.running = true;
    const tick = (): void => {
      void this.poll(deviceIdProvider());
    };
    this.timer = setInterval(tick, this.pollIntervalMs);
    this.timer.unref();
    tick();
    void this.subscribe();
  }

  /** Reconnects the SSE stream after a disconnect. */
  private async subscribe(): Promise<void> {
    if (!this.running) return;
    const controller = new AbortController();
    this.controller = controller;
    try {
      const response = await this.fetchImpl(`${this.baseUrl}/v1/stream`, {
        signal: controller.signal,
        headers: { accept: 'text/event-stream' },
      });
      if (!response.ok || response.body === null) throw new Error(`stream status ${response.status}`);
      this.status.streamConnected = true;
      this.logger('posture.stream_connected', {});
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (this.running) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const events = buffer.split('\n\n');
        buffer = events.pop() ?? '';
        for (const chunk of events) this.handleEvent(chunk);
      }
    } catch (error) {
      if (!this.running) return;
      this.logger('posture.stream_error', { error: error instanceof Error ? error.message : String(error) });
    } finally {
      this.status.streamConnected = false;
      if (this.running) {
        const retry = setTimeout(() => void this.subscribe(), 2000);
        retry.unref();
      }
    }
  }

  private handleEvent(chunk: string): void {
    const dataLine = chunk
      .split('\n')
      .find((line) => line.startsWith('data:'));
    if (dataLine === undefined) return;
    let event: Record<string, unknown>;
    try {
      event = JSON.parse(dataLine.slice(5).trim()) as Record<string, unknown>;
    } catch {
      return;
    }
    if (event.type !== 'posture' || typeof event.deviceId !== 'string') return;
    const deviceId = event.deviceId;
    void (async () => {
      const report = await this.fetchReport(deviceId);
      if (report === null) return;
      this.writeSnapshot(report, deviceId, new Date());
      this.status.lastPushAt = new Date();
      this.onChange?.(deviceId);
    })();
  }

  private writeSnapshot(report: PostureReport, deviceId: string, receivedAt: Date): void {
    const snapshot: PostureSnapshotRecord = {
      deviceId,
      osName: String(report.osName ?? 'unknown'),
      osVersion: String(report.osVersion ?? '0.0.0'),
      diskEncrypted: Boolean(report.diskEncrypted),
      edrOnline: Boolean(report.edrOnline),
      edrProduct: String(report.edrProduct ?? 'none'),
      firewallEnabled: Boolean(report.firewallEnabled),
      screenLockSeconds:
        typeof report.screenLockSeconds === 'number' ? report.screenLockSeconds : null,
      patchLevel: String(report.patchLevel ?? 'unknown'),
      collectedAt: clampCollectedAt(report.collectedAt, receivedAt),
      receivedAt: receivedAt.toISOString(),
      source: 'agent',
      reportedBy: 'posture-service',
    };
    this.store.upsert(snapshot);
    this.onChange?.(deviceId);
  }

  stop(): void {
    this.running = false;
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
    this.controller?.abort();
    this.controller = null;
    this.status.streamConnected = false;
  }
}

/**
 * Guards against a compromised or misconfigured agent reporting a future
 * collection time, which would make stale posture look fresh forever. Times
 * more than 5 minutes ahead of receipt are clamped to receipt time.
 */
export function clampCollectedAt(value: unknown, receivedAt: Date): string {
  if (typeof value !== 'string') return receivedAt.toISOString();
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return receivedAt.toISOString();
  const skew = 5 * 60 * 1000;
  if (parsed.getTime() > receivedAt.getTime() + skew) return receivedAt.toISOString();
  return parsed.toISOString();
}
