/**
 * SQLite persistence via node:sqlite (synchronous, single process).
 *
 * The store is intentionally boring: one writer, WAL mode, explicit schema
 * versioning. Every mutating method is synchronous so callers cannot interleave
 * half-applied state transitions.
 */
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export type DB = DatabaseSync;

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  roles_json    TEXT NOT NULL,
  group_name    TEXT NOT NULL,
  disabled      INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id                   TEXT PRIMARY KEY,
  display_name         TEXT NOT NULL,
  owner_user_id        TEXT,
  group_name           TEXT,
  cert_serial          TEXT NOT NULL,
  cert_fingerprint256  TEXT NOT NULL UNIQUE,
  cert_issued_at       TEXT NOT NULL,
  cert_expires_at      TEXT NOT NULL,
  status               TEXT NOT NULL CHECK (status IN ('enrolled','revoked')),
  enrolled_at          TEXT NOT NULL,
  revoked_at           TEXT,
  revoked_reason       TEXT,
  last_seen_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_devices_fp ON devices(cert_fingerprint256);

CREATE TABLE IF NOT EXISTS sessions (
  id                  TEXT PRIMARY KEY,
  user_id             TEXT NOT NULL REFERENCES users(id),
  device_id           TEXT NOT NULL REFERENCES devices(id),
  cert_fingerprint256 TEXT NOT NULL,
  ip                  TEXT NOT NULL,
  user_agent          TEXT NOT NULL,
  state               TEXT NOT NULL CHECK (state IN ('active','revoked','expired')),
  created_at          TEXT NOT NULL,
  last_seen_at        TEXT NOT NULL,
  expires_at          TEXT NOT NULL,
  revoked_at          TEXT,
  revoke_reason       TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state);

CREATE TABLE IF NOT EXISTS grants (
  id                  TEXT PRIMARY KEY,
  session_id          TEXT NOT NULL REFERENCES sessions(id),
  user_id             TEXT NOT NULL,
  device_id           TEXT NOT NULL,
  app_id              TEXT NOT NULL,
  state               TEXT NOT NULL CHECK (state IN ('active','revoked','expired')),
  created_at          TEXT NOT NULL,
  last_evaluated_at   TEXT NOT NULL,
  expires_at          TEXT NOT NULL,
  revoked_at          TEXT,
  revoke_reason       TEXT,
  last_decision       TEXT NOT NULL CHECK (last_decision IN ('allow','deny')),
  last_reason         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_grants_session ON grants(session_id);
CREATE INDEX IF NOT EXISTS idx_grants_app ON grants(app_id);
CREATE INDEX IF NOT EXISTS idx_grants_state ON grants(state);

CREATE TABLE IF NOT EXISTS posture (
  device_id         TEXT PRIMARY KEY REFERENCES devices(id),
  os_name           TEXT NOT NULL,
  os_version        TEXT NOT NULL,
  disk_encrypted    INTEGER NOT NULL,
  edr_online        INTEGER NOT NULL,
  edr_product       TEXT NOT NULL,
  firewall_enabled  INTEGER NOT NULL,
  screen_lock_secs  INTEGER,
  patch_level       TEXT NOT NULL,
  collected_at      TEXT NOT NULL,
  received_at       TEXT NOT NULL,
  source            TEXT NOT NULL,
  reported_by       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  actor_type  TEXT NOT NULL,
  actor_id    TEXT NOT NULL,
  action      TEXT NOT NULL,
  decision    TEXT NOT NULL,
  reason      TEXT NOT NULL,
  app_id      TEXT,
  session_id  TEXT,
  device_id   TEXT,
  user_id     TEXT,
  ip          TEXT,
  detail_json TEXT NOT NULL,
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action);
CREATE INDEX IF NOT EXISTS idx_audit_device ON audit(device_id);

CREATE TABLE IF NOT EXISTS auth_failures (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        TEXT NOT NULL,
  username  TEXT NOT NULL,
  device_id TEXT NOT NULL,
  ip        TEXT NOT NULL,
  reason    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_failures_lookup ON auth_failures(username, ts);
`;

export function openDatabase(dbPath: string): DB {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
  }
  const db = new DatabaseSync(dbPath);
  db.exec(SCHEMA);
  if (dbPath !== ':memory:') {
    fs.chmodSync(dbPath, 0o600);
  }
  return db;
}

export function closeDatabase(db: DB): void {
  db.close();
}

/** Runs `fn` inside a transaction; rolls back if it throws. */
export function transaction<T>(db: DB, fn: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}
