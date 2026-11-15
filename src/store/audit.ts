/**
 * Append-only audit log with a SHA-256 hash chain and periodic HMAC anchors.
 *
 * Threat model: an attacker who can write to the database should not be able
 * to silently delete or edit history. Each record commits to its predecessor,
 * and every `ANCHOR_EVERY` records the current head is HMACed with a key
 * derived from the session secret and stored separately. Without that secret
 * the chain cannot be rewritten coherently.
 */
import type { DB } from './db.ts';
import type { AuditDecision, AuditRecord } from './types.ts';
import { canonicalJson, hmacHex, sha256Hex } from '../crypto/hash.ts';
import { newId } from '../util/ids.ts';

export interface AuditInput {
  actorType: AuditRecord['actorType'];
  actorId: string;
  action: string;
  decision: AuditDecision;
  reason: string;
  appId?: string | null;
  sessionId?: string | null;
  deviceId?: string | null;
  userId?: string | null;
  ip?: string | null;
  detail?: Record<string, unknown>;
}

const ANCHOR_EVERY = 64;
const GENESIS_HASH = '0'.repeat(64);

type Row = Record<string, unknown>;
const asString = (value: unknown): string => (typeof value === 'string' ? value : '');
const asNullable = (value: unknown): string | null => (typeof value === 'string' ? value : null);

function mapAudit(row: Row): AuditRecord {
  return {
    id: Number(row.id),
    ts: asString(row.ts),
    actorType: asString(row.actor_type) as AuditRecord['actorType'],
    actorId: asString(row.actor_id),
    action: asString(row.action),
    decision: asString(row.decision) as AuditDecision,
    reason: asString(row.reason),
    appId: asNullable(row.app_id),
    sessionId: asNullable(row.session_id),
    deviceId: asNullable(row.device_id),
    userId: asNullable(row.user_id),
    ip: asNullable(row.ip),
    detail: JSON.parse(asString(row.detail_json)) as Record<string, unknown>,
    prevHash: asString(row.prev_hash),
    hash: asString(row.hash),
  };
}

function recordDigest(record: Omit<AuditRecord, 'id' | 'hash'>): string {
  return sha256Hex(canonicalJson(record));
}

export interface ChainVerification {
  ok: boolean;
  records: number;
  anchors: number;
  brokenAt: number | null;
  message: string;
}

export class AuditLog {
  private readonly db: DB;
  private readonly anchorKey: Buffer;

  constructor(db: DB, secret: string) {
    this.db = db;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_anchors (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        audit_id    INTEGER NOT NULL,
        head_hash   TEXT NOT NULL,
        mac         TEXT NOT NULL,
        created_at  TEXT NOT NULL
      );
    `);
    this.anchorKey = Buffer.from(sha256Hex(`audit-anchor:${secret}`), 'hex');
  }

  /** Appends one record and returns it. Never throws on duplicate content. */
  append(input: AuditInput): AuditRecord {
    const head = this.db
      .prepare('SELECT hash FROM audit ORDER BY id DESC LIMIT 1')
      .get() as Row | undefined;
    const prevHash = head ? asString(head.hash) : GENESIS_HASH;
    const ts = new Date().toISOString();
    const base: Omit<AuditRecord, 'id' | 'hash'> = {
      ts,
      actorType: input.actorType,
      actorId: input.actorId,
      action: input.action,
      decision: input.decision,
      reason: input.reason,
      appId: input.appId ?? null,
      sessionId: input.sessionId ?? null,
      deviceId: input.deviceId ?? null,
      userId: input.userId ?? null,
      ip: input.ip ?? null,
      detail: input.detail ?? {},
      prevHash,
    };
    const hash = recordDigest(base);
    const result = this.db
      .prepare(
        `INSERT INTO audit (ts, actor_type, actor_id, action, decision, reason, app_id, session_id,
           device_id, user_id, ip, detail_json, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        base.ts,
        base.actorType,
        base.actorId,
        base.action,
        base.decision,
        base.reason,
        base.appId,
        base.sessionId,
        base.deviceId,
        base.userId,
        base.ip,
        JSON.stringify(base.detail),
        base.prevHash,
        hash,
      );
    const id = Number(result.lastInsertRowid);
    if (id % ANCHOR_EVERY === 0) this.anchor(id, hash, ts);
    return { ...base, id, hash };
  }

  private anchor(auditId: number, headHash: string, ts: string): void {
    const mac = hmacHex(this.anchorKey, `${auditId}:${headHash}`);
    this.db
      .prepare('INSERT INTO audit_anchors (audit_id, head_hash, mac, created_at) VALUES (?, ?, ?, ?)')
      .run(auditId, headHash, mac, ts);
  }

  /** Most recent records, newest first. */
  recent(limit = 100, filters: { action?: string; deviceId?: string; decision?: string } = {}): AuditRecord[] {
    const clauses: string[] = [];
    const params: (string | number)[] = [];
    if (filters.action) {
      clauses.push('action = ?');
      params.push(filters.action);
    }
    if (filters.deviceId) {
      clauses.push('device_id = ?');
      params.push(filters.deviceId);
    }
    if (filters.decision) {
      clauses.push('decision = ?');
      params.push(filters.decision);
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    params.push(Math.max(1, Math.min(limit, 1000)));
    return (
      this.db
        .prepare(`SELECT * FROM audit ${where} ORDER BY id DESC LIMIT ?`)
        .all(...params) as Row[]
    ).map(mapAudit);
  }

  count(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM audit').get() as Row;
    return Number(row.n);
  }

  /** Recomputes the entire chain and validates every anchor. */
  verify(): ChainVerification {
    const rows = this.db.prepare('SELECT * FROM audit ORDER BY id').all() as Row[];
    const anchors = this.db
      .prepare('SELECT * FROM audit_anchors ORDER BY audit_id')
      .all() as Row[];
    const anchorByAuditId = new Map<number, Row>();
    for (const anchor of anchors) anchorByAuditId.set(Number(anchor.audit_id), anchor);

    let prevHash = GENESIS_HASH;
    let count = 0;
    for (const row of rows) {
      const record = mapAudit(row);
      if (record.prevHash !== prevHash) {
        return {
          ok: false,
          records: count,
          anchors: anchors.length,
          brokenAt: record.id,
          message: `hash chain break at record ${record.id}`,
        };
      }
      const { id, hash, ...rest } = record;
      void id;
      const expected = recordDigest(rest);
      if (expected !== hash) {
        return {
          ok: false,
          records: count,
          anchors: anchors.length,
          brokenAt: record.id,
          message: `record ${record.id} has been modified`,
        };
      }
      const anchor = anchorByAuditId.get(record.id);
      if (anchor) {
        const mac = hmacHex(this.anchorKey, `${record.id}:${record.hash}`);
        if (mac !== asString(anchor.mac) || record.hash !== asString(anchor.head_hash)) {
          return {
            ok: false,
            records: count,
            anchors: anchors.length,
            brokenAt: record.id,
            message: `anchor at record ${record.id} does not match`,
          };
        }
      }
      prevHash = hash;
      count += 1;
    }
    return {
      ok: true,
      records: count,
      anchors: anchors.length,
      brokenAt: null,
      message: `verified ${count} records across ${anchors.length} anchors`,
    };
  }

  /** JSONL export of the chain, oldest first, for SIEM ingestion. */
  toJsonl(limit = 5000): string {
    const rows = this.db.prepare('SELECT * FROM audit ORDER BY id LIMIT ?').all(limit) as Row[];
    return rows.map((row) => JSON.stringify(mapAudit(row))).join('\n');
  }
}

/** Convenience for tests and the admin UI: a fresh opaque audit request id. */
export function auditRequestId(): string {
  return newId('req');
}
