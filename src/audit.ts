/**
 * Append-only, tamper-evident audit log.
 *
 * Each record carries the hash of the previous record, so deleting or editing
 * a record breaks the chain and `verifyChain` reports it. The same entry is
 * also kept in a bounded in-memory ring so the admin page can show recent
 * events without re-reading the whole file.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalJson, nowIso, sha256Hex, truncate } from './util.ts';
import { createLogger } from './log.ts';

const log = createLogger('audit');

export type AuditEventType =
  | 'auth.login.success'
  | 'auth.login.denied'
  | 'auth.login.rate_limited'
  | 'auth.logout'
  | 'device.check.pass'
  | 'device.check.fail'
  | 'access.allow'
  | 'access.deny'
  | 'session.revoked'
  | 'session.expired'
  | 'posture.recheck'
  | 'admin.device.revoked'
  | 'admin.device.restored'
  | 'admin.viewed';

export type AuditOutcome = 'allow' | 'deny' | 'info';

export interface AuditEntry {
  seq: number;
  ts: string;
  event: AuditEventType;
  outcome: AuditOutcome;
  actor?: { userId?: string; deviceId?: string; ip?: string };
  appId?: string;
  sessionId?: string;
  reasonCodes?: string[];
  message?: string;
  detail?: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

export type AuditDraft = Omit<AuditEntry, 'seq' | 'ts' | 'prevHash' | 'hash'>;

const GENESIS = '0'.repeat(64);

export interface AuditLogOptions {
  filePath: string;
  memoryLimit?: number;
}

export class AuditLog {
  readonly filePath: string;
  private readonly memoryLimit: number;
  private ring: AuditEntry[] = [];
  private headHash = GENESIS;
  private nextSeq = 1;
  private readonly testMode: boolean;

  constructor(options: AuditLogOptions) {
    this.filePath = options.filePath;
    this.memoryLimit = options.memoryLimit ?? 500;
    this.testMode = options.filePath === '';
    if (!this.testMode) {
      mkdirSync(dirname(this.filePath), { recursive: true });
      this.recover();
    }
  }

  /** Restore the chain head from an existing log file. */
  private recover(): void {
    if (!existsSync(this.filePath)) return;
    const lines = readFileSync(this.filePath, 'utf8').split('\n').filter(Boolean);
    if (lines.length === 0) return;
    const entries: AuditEntry[] = [];
    for (const line of lines) {
      try {
        entries.push(JSON.parse(line) as AuditEntry);
      } catch {
        // Keep the chain head anchored to the last parsable record; an
        // unparsable trailing line usually means a torn write.
        log.warn('skipping unparsable audit line', { file: this.filePath });
      }
    }
    const last = entries.at(-1);
    if (last) {
      this.headHash = last.hash;
      this.nextSeq = last.seq + 1;
    }
    this.ring = entries.slice(-this.memoryLimit);
  }

  record(draft: AuditDraft, now = Date.now()): AuditEntry {
    const seq = this.nextSeq++;
    const ts = nowIso(now);
    const prevHash = this.headHash;
    const unsigned = {
      seq,
      ts,
      event: draft.event,
      outcome: draft.outcome,
      actor: draft.actor,
      appId: draft.appId,
      sessionId: draft.sessionId,
      reasonCodes: draft.reasonCodes,
      message: draft.message && truncate(draft.message, 500),
      detail: draft.detail,
      prevHash,
    };
    const hash = sha256Hex(canonicalJson(unsigned));
    const entry: AuditEntry = { ...unsigned, hash };
    this.headHash = hash;
    this.ring.push(entry);
    if (this.ring.length > this.memoryLimit) this.ring.shift();
    if (!this.testMode) {
      try {
        appendFileSync(this.filePath, `${JSON.stringify(entry)}\n`, 'utf8');
      } catch (error) {
        // Never fail a security decision because logging failed, but make it
        // loud: a lost audit line is a compliance problem.
        log.error('failed to append audit record', { error: (error as Error).message });
      }
    }
    return entry;
  }

  recent(limit = 50, filter?: { event?: string; outcome?: string; userId?: string; deviceId?: string; appId?: string }): AuditEntry[] {
    let rows = this.ring;
    if (filter) {
      rows = rows.filter((entry) => {
        if (filter.event && entry.event !== filter.event) return false;
        if (filter.outcome && entry.outcome !== filter.outcome) return false;
        if (filter.userId && entry.actor?.userId !== filter.userId) return false;
        if (filter.deviceId && entry.actor?.deviceId !== filter.deviceId) return false;
        if (filter.appId && entry.appId !== filter.appId) return false;
        return true;
      });
    }
    return rows.slice(-Math.max(1, limit)).reverse();
  }

  /** Recompute the chain over the on-disk file (or the ring in test mode). */
  verifyChain(): { valid: boolean; entries: number; brokenAt?: number } {
    const lines = this.testMode
      ? this.ring.map((entry) => JSON.stringify(entry))
      : (existsSync(this.filePath) ? readFileSync(this.filePath, 'utf8').split('\n').filter(Boolean) : []);
    let prevHash = GENESIS;
    let expectedSeq = 1;
    let count = 0;
    for (const line of lines) {
      let entry: AuditEntry;
      try {
        entry = JSON.parse(line) as AuditEntry;
      } catch {
        return { valid: false, entries: count, brokenAt: expectedSeq };
      }
      const unsigned = {
        seq: entry.seq,
        ts: entry.ts,
        event: entry.event,
        outcome: entry.outcome,
        actor: entry.actor,
        appId: entry.appId,
        sessionId: entry.sessionId,
        reasonCodes: entry.reasonCodes,
        message: entry.message,
        detail: entry.detail,
        prevHash: entry.prevHash,
      };
      const hash = sha256Hex(canonicalJson(unsigned));
      if (entry.seq !== expectedSeq || entry.prevHash !== prevHash || entry.hash !== hash) {
        return { valid: false, entries: count, brokenAt: entry.seq };
      }
      prevHash = entry.hash;
      expectedSeq += 1;
      count += 1;
    }
    return { valid: true, entries: count };
  }
}
