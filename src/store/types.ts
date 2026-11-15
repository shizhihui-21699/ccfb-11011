export type Role = 'admin' | 'employee';

export interface UserRecord {
  id: string;
  username: string;
  displayName: string;
  passwordHash: string;
  roles: Role[];
  group: string;
  disabled: boolean;
  createdAt: string;
}

export type DeviceStatus = 'enrolled' | 'revoked';

export interface DeviceRecord {
  id: string;
  displayName: string;
  ownerUserId: string | null;
  group: string | null;
  certSerial: string;
  certFingerprint256: string;
  certIssuedAt: string;
  certExpiresAt: string;
  status: DeviceStatus;
  enrolledAt: string;
  revokedAt: string | null;
  revokedReason: string | null;
  lastSeenAt: string | null;
}

export type SessionState = 'active' | 'revoked' | 'expired';

/**
 * A login session is created once the user authenticates through a device's
 * client certificate. Per-application authorizations are represented by
 * separate `accessGrants`, each re-evaluated independently.
 */
export interface SessionRecord {
  id: string;
  userId: string;
  deviceId: string;
  certFingerprint256: string;
  ip: string;
  userAgent: string;
  state: SessionState;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  revokedAt: string | null;
  revokeReason: string | null;
}

export interface GrantRecord {
  id: string;
  sessionId: string;
  userId: string;
  deviceId: string;
  appId: string;
  state: SessionState;
  createdAt: string;
  lastEvaluatedAt: string;
  expiresAt: string;
  revokedAt: string | null;
  revokeReason: string | null;
  lastDecision: 'allow' | 'deny';
  lastReason: string;
}

export type PostureSource = 'agent' | 'admin' | 'seed';

export interface PostureSnapshotRecord {
  deviceId: string;
  osName: string;
  osVersion: string;
  diskEncrypted: boolean;
  edrOnline: boolean;
  edrProduct: string;
  firewallEnabled: boolean;
  screenLockSeconds: number | null;
  patchLevel: string;
  collectedAt: string;
  receivedAt: string;
  source: PostureSource;
  reportedBy: string;
}

export type AuditDecision = 'allow' | 'deny' | 'info';

export interface AuditRecord {
  id: number;
  ts: string;
  actorType: 'user' | 'device' | 'system' | 'admin';
  actorId: string;
  action: string;
  decision: AuditDecision;
  reason: string;
  appId: string | null;
  sessionId: string | null;
  deviceId: string | null;
  userId: string | null;
  ip: string | null;
  detail: Record<string, unknown>;
  prevHash: string;
  hash: string;
}
