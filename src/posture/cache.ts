/**
 * Proxy-side posture cache.
 *
 * The proxy never trusts posture data supplied by the device's own request;
 * it pulls from the posture service (authenticated with a service token) and
 * caches briefly. Re-evaluation runs on a timer so a degradation is noticed
 * even when the user is idle, which is what makes the 60s revocation SLA
 * achievable rather than dependent on the next request.
 */
import type { PostureFacts, PostureRecord } from '../types.ts';
import { nowIso } from '../util.ts';
import type { Logger } from '../log.ts';

export interface PostureSnapshot {
  record: PostureRecord | null;
  fetchedAt: number;
  error?: string;
  /** True when the response came from cache rather than a live fetch. */
  cached: boolean;
}

export interface PostureSource {
  fetch(deviceId: string): Promise<PostureRecord | null>;
}

export class HttpPostureSource implements PostureSource {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly timeoutMs: number;
  private readonly log: Logger;

  constructor(baseUrl: string, token: string, timeoutMs: number, log: Logger) {
    this.baseUrl = baseUrl;
    this.token = token;
    this.timeoutMs = timeoutMs;
    this.log = log;
  }

  async fetch(deviceId: string): Promise<PostureRecord | null> {
    const url = `${this.baseUrl}/v1/posture/${encodeURIComponent(deviceId)}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(url, {
        headers: { authorization: `Bearer ${this.token}`, accept: 'application/json' },
        signal: controller.signal,
      });
      if (response.status === 404) return null;
      if (!response.ok) throw new Error(`posture service returned ${response.status}`);
      const body = (await response.json()) as { record?: PostureRecord };
      if (!body.record) return null;
      return normalizeRecord(deviceId, body.record);
    } catch (error) {
      this.log.warn('posture fetch failed', { deviceId, error: (error as Error).message });
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Used by tests and by "no posture service configured" deployments. */
export class StaticPostureSource implements PostureSource {
  private readonly records = new Map<string, PostureRecord>();

  set(deviceId: string, facts: PostureFacts | null): void {
    this.records.set(deviceId, { deviceId, facts, updatedAt: nowIso(), revision: 1 });
  }

  async fetch(deviceId: string): Promise<PostureRecord | null> {
    return this.records.get(deviceId) ?? null;
  }
}

function normalizeRecord(deviceId: string, record: PostureRecord): PostureRecord {
  return {
    ...record,
    deviceId,
    facts: record.facts ? { ...record.facts } : null,
  };
}

export interface PostureCacheOptions {
  source: PostureSource;
  ttlMs: number;
  log: Logger;
  /** After a fetch error, keep serving the last good snapshot for this long. */
  staleGraceMs?: number;
}

export class PostureCache {
  private readonly source: PostureSource;
  private readonly ttlMs: number;
  private readonly staleGraceMs: number;
  private readonly log: Logger;
  private readonly entries = new Map<string, PostureSnapshot>();
  private readonly inflight = new Map<string, Promise<PostureSnapshot>>();

  constructor(options: PostureCacheOptions) {
    this.source = options.source;
    this.ttlMs = options.ttlMs;
    this.staleGraceMs = options.staleGraceMs ?? Math.max(options.ttlMs, 5_000);
    this.log = options.log;
  }

  peek(deviceId: string): PostureSnapshot {
    return this.entries.get(deviceId) ?? { record: null, fetchedAt: 0, cached: true };
  }

  /** Fetch with coalescing so a burst of rechecks causes one upstream call. */
  async get(deviceId: string, now = Date.now()): Promise<PostureSnapshot> {
    const existing = this.entries.get(deviceId);
    if (existing && now - existing.fetchedAt < this.ttlMs && !existing.error) {
      return { ...existing, cached: true };
    }
    const inflight = this.inflight.get(deviceId);
    if (inflight) return inflight;

    const promise = (async (): Promise<PostureSnapshot> => {
      try {
        const record = await this.source.fetch(deviceId);
        const snapshot: PostureSnapshot = { record, fetchedAt: now, cached: false };
        this.entries.set(deviceId, snapshot);
        return snapshot;
      } catch (error) {
        const message = (error as Error).message;
        const previous = this.entries.get(deviceId);
        // A brief outage should not mass-revoke every session; but a long one
        // must fail closed, so stale data is only served for a short grace.
        if (previous && now - previous.fetchedAt < this.staleGraceMs) {
          this.log.warn('serving stale posture after fetch error', { deviceId, error: message });
          return { ...previous, cached: true, error: message };
        }
        const failed: PostureSnapshot = { record: null, fetchedAt: now, error: message, cached: false };
        this.entries.set(deviceId, failed);
        return failed;
      } finally {
        this.inflight.delete(deviceId);
      }
    })();
    this.inflight.set(deviceId, promise);
    return promise;
  }

  invalidate(deviceId: string): void {
    this.entries.delete(deviceId);
  }

  clear(): void {
    this.entries.clear();
  }
}
