/**
 * Posture service storage. Kept separate from the proxy so the proxy has no
 * write path for the data it enforces on.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { PostureFacts, PostureRecord } from '../types.ts';
import { nowIso } from '../util.ts';

export interface StoredPostureFile {
  version: 1;
  records: PostureRecord[];
}

export class PostureStore {
  private readonly filePath: string;
  private readonly records = new Map<string, PostureRecord>();
  private dirty = false;
  private flushTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(filePath: string) {
    this.filePath = filePath;
    if (existsSync(filePath)) {
      const raw = JSON.parse(readFileSync(filePath, 'utf8')) as StoredPostureFile;
      if (raw.version === 1 && Array.isArray(raw.records)) {
        for (const record of raw.records) this.records.set(record.deviceId, record);
      }
    }
  }

  get(deviceId: string): PostureRecord | null {
    const record = this.records.get(deviceId);
    return record ? structuredClone(record) : null;
  }

  list(): PostureRecord[] {
    return [...this.records.values()].map((record) => structuredClone(record)).sort((a, b) => a.deviceId.localeCompare(b.deviceId));
  }

  upsert(deviceId: string, facts: PostureFacts): PostureRecord {
    const previous = this.records.get(deviceId);
    const record: PostureRecord = {
      deviceId,
      facts: { ...facts },
      updatedAt: nowIso(),
      revision: (previous?.revision ?? 0) + 1,
    };
    this.records.set(deviceId, record);
    this.scheduleFlush();
    return structuredClone(record);
  }

  private scheduleFlush(): void {
    this.dirty = true;
    if (this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = undefined;
      if (this.dirty) this.flush();
    }, 250);
    this.flushTimer.unref?.();
  }

  flush(): void {
    this.dirty = false;
    mkdirSync(dirname(this.filePath), { recursive: true });
    const payload: StoredPostureFile = { version: 1, records: this.list() };
    const tmp = `${this.filePath}.tmp-${process.pid}`;
    writeFileSync(tmp, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    renameSync(tmp, this.filePath);
  }

  close(): void {
    if (this.flushTimer) clearTimeout(this.flushTimer);
    if (this.dirty) this.flush();
  }
}
