import type { DB } from './db.ts';
import type {
  DeviceRecord,
  DeviceStatus,
  GrantRecord,
  PostureSnapshotRecord,
  PostureSource,
  Role,
  SessionRecord,
  SessionState,
  UserRecord,
} from './types.ts';

type Row = Record<string, unknown>;

function asString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}
function asNullableString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}
function asNumber(value: unknown): number {
  return typeof value === 'number' ? value : Number(value ?? 0);
}
function asBoolean(value: unknown): boolean {
  return asNumber(value) !== 0;
}

function mapUser(row: Row): UserRecord {
  return {
    id: asString(row.id),
    username: asString(row.username),
    displayName: asString(row.display_name),
    passwordHash: asString(row.password_hash),
    roles: JSON.parse(asString(row.roles_json)) as Role[],
    group: asString(row.group_name),
    disabled: asBoolean(row.disabled),
    createdAt: asString(row.created_at),
  };
}

function mapDevice(row: Row): DeviceRecord {
  return {
    id: asString(row.id),
    displayName: asString(row.display_name),
    ownerUserId: asNullableString(row.owner_user_id),
    group: asNullableString(row.group_name),
    certSerial: asString(row.cert_serial),
    certFingerprint256: asString(row.cert_fingerprint256),
    certIssuedAt: asString(row.cert_issued_at),
    certExpiresAt: asString(row.cert_expires_at),
    status: asString(row.status) as DeviceStatus,
    enrolledAt: asString(row.enrolled_at),
    revokedAt: asNullableString(row.revoked_at),
    revokedReason: asNullableString(row.revoked_reason),
    lastSeenAt: asNullableString(row.last_seen_at),
  };
}

function mapSession(row: Row): SessionRecord {
  return {
    id: asString(row.id),
    userId: asString(row.user_id),
    deviceId: asString(row.device_id),
    certFingerprint256: asString(row.cert_fingerprint256),
    ip: asString(row.ip),
    userAgent: asString(row.user_agent),
    state: asString(row.state) as SessionState,
    createdAt: asString(row.created_at),
    lastSeenAt: asString(row.last_seen_at),
    expiresAt: asString(row.expires_at),
    revokedAt: asNullableString(row.revoked_at),
    revokeReason: asNullableString(row.revoke_reason),
  };
}

function mapGrant(row: Row): GrantRecord {
  return {
    id: asString(row.id),
    sessionId: asString(row.session_id),
    userId: asString(row.user_id),
    deviceId: asString(row.device_id),
    appId: asString(row.app_id),
    state: asString(row.state) as SessionState,
    createdAt: asString(row.created_at),
    lastEvaluatedAt: asString(row.last_evaluated_at),
    expiresAt: asString(row.expires_at),
    revokedAt: asNullableString(row.revoked_at),
    revokeReason: asNullableString(row.revoke_reason),
    lastDecision: asString(row.last_decision) as 'allow' | 'deny',
    lastReason: asString(row.last_reason),
  };
}

function mapPosture(row: Row): PostureSnapshotRecord {
  return {
    deviceId: asString(row.device_id),
    osName: asString(row.os_name),
    osVersion: asString(row.os_version),
    diskEncrypted: asBoolean(row.disk_encrypted),
    edrOnline: asBoolean(row.edr_online),
    edrProduct: asString(row.edr_product),
    firewallEnabled: asBoolean(row.firewall_enabled),
    screenLockSeconds:
      row.screen_lock_secs === null || row.screen_lock_secs === undefined
        ? null
        : asNumber(row.screen_lock_secs),
    patchLevel: asString(row.patch_level),
    collectedAt: asString(row.collected_at),
    receivedAt: asString(row.received_at),
    source: asString(row.source) as PostureSource,
    reportedBy: asString(row.reported_by),
  };
}

export class UserStore {
  private readonly db: DB;

  constructor(db: DB) {
    this.db = db;
  }

  findByUsername(username: string): UserRecord | null {
    const row = this.db
      .prepare('SELECT * FROM users WHERE username = ?')
      .get(username.toLowerCase()) as Row | undefined;
    return row ? mapUser(row) : null;
  }

  findById(id: string): UserRecord | null {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as Row | undefined;
    return row ? mapUser(row) : null;
  }

  list(): UserRecord[] {
    return (this.db.prepare('SELECT * FROM users ORDER BY username').all() as Row[]).map(mapUser);
  }

  count(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM users').get() as Row;
    return asNumber(row.n);
  }

  insert(user: UserRecord): void {
    this.db
      .prepare(
        `INSERT INTO users (id, username, display_name, password_hash, roles_json, group_name, disabled, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        user.id,
        user.username.toLowerCase(),
        user.displayName,
        user.passwordHash,
        JSON.stringify(user.roles),
        user.group,
        user.disabled ? 1 : 0,
        user.createdAt,
      );
  }

  setDisabled(id: string, disabled: boolean): void {
    this.db.prepare('UPDATE users SET disabled = ? WHERE id = ?').run(disabled ? 1 : 0, id);
  }
}

export class DeviceStore {
  private readonly db: DB;

  constructor(db: DB) {
    this.db = db;
  }

  findById(id: string): DeviceRecord | null {
    const row = this.db.prepare('SELECT * FROM devices WHERE id = ?').get(id) as Row | undefined;
    return row ? mapDevice(row) : null;
  }

  findByFingerprint(fingerprint: string): DeviceRecord | null {
    const row = this.db
      .prepare('SELECT * FROM devices WHERE cert_fingerprint256 = ?')
      .get(fingerprint) as Row | undefined;
    return row ? mapDevice(row) : null;
  }

  list(): DeviceRecord[] {
    return (this.db.prepare('SELECT * FROM devices ORDER BY id').all() as Row[]).map(mapDevice);
  }

  upsert(device: DeviceRecord): void {
    this.db
      .prepare(
        `INSERT INTO devices (id, display_name, owner_user_id, group_name, cert_serial, cert_fingerprint256,
           cert_issued_at, cert_expires_at, status, enrolled_at, revoked_at, revoked_reason, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           display_name = excluded.display_name,
           owner_user_id = excluded.owner_user_id,
           group_name = excluded.group_name,
           cert_serial = excluded.cert_serial,
           cert_fingerprint256 = excluded.cert_fingerprint256,
           cert_issued_at = excluded.cert_issued_at,
           cert_expires_at = excluded.cert_expires_at,
           status = excluded.status,
           revoked_at = excluded.revoked_at,
           revoked_reason = excluded.revoked_reason`,
      )
      .run(
        device.id,
        device.displayName,
        device.ownerUserId,
        device.group,
        device.certSerial,
        device.certFingerprint256,
        device.certIssuedAt,
        device.certExpiresAt,
        device.status,
        device.enrolledAt,
        device.revokedAt,
        device.revokedReason,
        device.lastSeenAt,
      );
  }

  touch(id: string, at: string): void {
    this.db.prepare('UPDATE devices SET last_seen_at = ? WHERE id = ?').run(at, id);
  }

  revoke(id: string, at: string, reason: string): void {
    this.db
      .prepare("UPDATE devices SET status = 'revoked', revoked_at = ?, revoked_reason = ? WHERE id = ?")
      .run(at, reason, id);
  }
}

export class SessionStore {
  private readonly db: DB;

  constructor(db: DB) {
    this.db = db;
  }

  findById(id: string): SessionRecord | null {
    const row = this.db.prepare('SELECT * FROM sessions WHERE id = ?').get(id) as Row | undefined;
    return row ? mapSession(row) : null;
  }

  listActive(): SessionRecord[] {
    return (
      this.db.prepare("SELECT * FROM sessions WHERE state = 'active' ORDER BY created_at").all() as Row[]
    ).map(mapSession);
  }

  countActive(): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS n FROM sessions WHERE state = 'active'")
      .get() as Row;
    return asNumber(row.n);
  }

  insert(session: SessionRecord): void {
    this.db
      .prepare(
        `INSERT INTO sessions (id, user_id, device_id, cert_fingerprint256, ip, user_agent, state,
           created_at, last_seen_at, expires_at, revoked_at, revoke_reason)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        session.id,
        session.userId,
        session.deviceId,
        session.certFingerprint256,
        session.ip,
        session.userAgent,
        session.state,
        session.createdAt,
        session.lastSeenAt,
        session.expiresAt,
        session.revokedAt,
        session.revokeReason,
      );
  }

  touch(id: string, at: string): void {
    this.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(at, id);
  }

  setState(id: string, state: SessionState, at: string | null, reason: string | null): void {
    this.db
      .prepare('UPDATE sessions SET state = ?, revoked_at = ?, revoke_reason = ? WHERE id = ?')
      .run(state, at, reason, id);
  }

  /**
   * Expires sessions past their TTL. Returns the ids that transitioned so the
   * caller can revoke their grants and write audit records.
   */
  expireDue(now: string): string[] {
    const due = this.db
      .prepare("SELECT id FROM sessions WHERE state = 'active' AND expires_at <= ?")
      .all(now) as Row[];
    const ids = due.map((row) => asString(row.id));
    if (ids.length > 0) {
      const update = this.db.prepare(
        "UPDATE sessions SET state = 'expired' WHERE state = 'active' AND expires_at <= ?",
      );
      update.run(now);
    }
    return ids;
  }
}

export class GrantStore {
  private readonly db: DB;

  constructor(db: DB) {
    this.db = db;
  }

  findById(id: string): GrantRecord | null {
    const row = this.db.prepare('SELECT * FROM grants WHERE id = ?').get(id) as Row | undefined;
    return row ? mapGrant(row) : null;
  }

  findBySessionApp(sessionId: string, appId: string): GrantRecord | null {
    const row = this.db
      .prepare(
        "SELECT * FROM grants WHERE session_id = ? AND app_id = ? AND state = 'active' ORDER BY created_at DESC",
      )
      .get(sessionId, appId) as Row | undefined;
    return row ? mapGrant(row) : null;
  }

  listActive(): GrantRecord[] {
    return (
      this.db.prepare("SELECT * FROM grants WHERE state = 'active' ORDER BY created_at").all() as Row[]
    ).map(mapGrant);
  }

  listForSession(sessionId: string): GrantRecord[] {
    return (
      this.db.prepare('SELECT * FROM grants WHERE session_id = ? ORDER BY created_at').all(sessionId) as Row[]
    ).map(mapGrant);
  }

  countActive(): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS n FROM grants WHERE state = 'active'")
      .get() as Row;
    return asNumber(row.n);
  }

  insert(grant: GrantRecord): void {
    this.db
      .prepare(
        `INSERT INTO grants (id, session_id, user_id, device_id, app_id, state, created_at,
           last_evaluated_at, expires_at, revoked_at, revoke_reason, last_decision, last_reason)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        grant.id,
        grant.sessionId,
        grant.userId,
        grant.deviceId,
        grant.appId,
        grant.state,
        grant.createdAt,
        grant.lastEvaluatedAt,
        grant.expiresAt,
        grant.revokedAt,
        grant.revokeReason,
        grant.lastDecision,
        grant.lastReason,
      );
  }

  touchEvaluation(id: string, at: string, decision: 'allow' | 'deny', reason: string): void {
    this.db
      .prepare('UPDATE grants SET last_evaluated_at = ?, last_decision = ?, last_reason = ? WHERE id = ?')
      .run(at, decision, reason, id);
  }

  revoke(id: string, at: string, reason: string): void {
    this.db
      .prepare(
        "UPDATE grants SET state = 'revoked', revoked_at = ?, revoke_reason = ? WHERE id = ? AND state = 'active'",
      )
      .run(at, reason, id);
  }

  revokeForSession(sessionId: string, at: string, reason: string): string[] {
    const rows = this.db
      .prepare("SELECT id FROM grants WHERE session_id = ? AND state = 'active'")
      .all(sessionId) as Row[];
    const ids = rows.map((row) => asString(row.id));
    if (ids.length > 0) {
      this.db
        .prepare(
          "UPDATE grants SET state = 'revoked', revoked_at = ?, revoke_reason = ? WHERE session_id = ? AND state = 'active'",
        )
        .run(at, reason, sessionId);
    }
    return ids;
  }

  expireDue(now: string): string[] {
    const due = this.db
      .prepare("SELECT id FROM grants WHERE state = 'active' AND expires_at <= ?")
      .all(now) as Row[];
    const ids = due.map((row) => asString(row.id));
    if (ids.length > 0) {
      this.db
        .prepare("UPDATE grants SET state = 'expired' WHERE state = 'active' AND expires_at <= ?")
        .run(now);
    }
    return ids;
  }
}

export class PostureStore {
  private readonly db: DB;

  constructor(db: DB) {
    this.db = db;
  }

  get(deviceId: string): PostureSnapshotRecord | null {
    const row = this.db.prepare('SELECT * FROM posture WHERE device_id = ?').get(deviceId) as Row | undefined;
    return row ? mapPosture(row) : null;
  }

  list(): PostureSnapshotRecord[] {
    return (this.db.prepare('SELECT * FROM posture ORDER BY device_id').all() as Row[]).map(mapPosture);
  }

  upsert(snapshot: PostureSnapshotRecord): void {
    this.db
      .prepare(
        `INSERT INTO posture (device_id, os_name, os_version, disk_encrypted, edr_online, edr_product,
           firewall_enabled, screen_lock_secs, patch_level, collected_at, received_at, source, reported_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(device_id) DO UPDATE SET
           os_name = excluded.os_name,
           os_version = excluded.os_version,
           disk_encrypted = excluded.disk_encrypted,
           edr_online = excluded.edr_online,
           edr_product = excluded.edr_product,
           firewall_enabled = excluded.firewall_enabled,
           screen_lock_secs = excluded.screen_lock_secs,
           patch_level = excluded.patch_level,
           collected_at = excluded.collected_at,
           received_at = excluded.received_at,
           source = excluded.source,
           reported_by = excluded.reported_by`,
      )
      .run(
        snapshot.deviceId,
        snapshot.osName,
        snapshot.osVersion,
        snapshot.diskEncrypted ? 1 : 0,
        snapshot.edrOnline ? 1 : 0,
        snapshot.edrProduct,
        snapshot.firewallEnabled ? 1 : 0,
        snapshot.screenLockSeconds,
        snapshot.patchLevel,
        snapshot.collectedAt,
        snapshot.receivedAt,
        snapshot.source,
        snapshot.reportedBy,
      );
  }
}
