/**
 * Shared domain types for the zero-trust access proxy.
 *
 * Configuration lives in plain JSON files so every decision input can be
 * version-controlled, diffed and audited.
 */

export type Platform = 'darwin' | 'win32' | 'linux';

export type DeviceStatus = 'active' | 'revoked';

export interface DeviceRecord {
  /** Stable device identifier parsed from the client certificate SAN URI. */
  id: string;
  label: string;
  platform: Platform;
  /** The user this device is assigned to. */
  assignedTo: string;
  status: DeviceStatus;
  /** SHA-256 fingerprint of the enrolled device certificate (colon hex). */
  certFingerprint256: string;
  certSubject: string;
  certSerial: string;
  certNotAfter: string;
  certPath?: string;
  keyPath?: string;
  enrolledAt: string;
  revokedAt?: string;
  revokeReason?: string;
}

export interface DeviceRegistryFile {
  version: 1;
  devices: DeviceRecord[];
}

export interface UserRecord {
  id: string;
  displayName: string;
  groups: string[];
  role: 'user' | 'admin';
  /** scrypt$N$r$p$saltHex$hashHex */
  passwordHash: string;
}

export interface UserDirectoryFile {
  version: 1;
  users: UserRecord[];
}

export interface PostureFacts {
  osVersion: string;
  osBuild?: string;
  diskEncrypted: boolean;
  edrInstalled: boolean;
  edrRunning: boolean;
  /** Last EDR heartbeat. A stale heartbeat means the EDR is not reporting. */
  edrLastHeartbeatAt: string | null;
  agentVersion?: string;
  /** When the posture service received the report (stamped by the service). */
  reportedAt: string | null;
  source: 'agent' | 'simulator';
}

export interface PostureRecord {
  deviceId: string;
  facts: PostureFacts | null;
  updatedAt: string;
  revision: number;
}

export type PostureStatus = 'healthy' | 'degraded' | 'unknown';

export interface PostureRequirements {
  /** Minimum version per platform, e.g. { darwin: "14.0", win32: "10.0.19045" }. */
  minOsVersion?: Partial<Record<Platform, string>>;
  requireDiskEncryption?: boolean;
  requireEdrInstalled?: boolean;
  requireEdrRunning?: boolean;
  maxEdrHeartbeatAgeSeconds?: number;
  maxReportAgeSeconds?: number;
  /** Optional 0-100 score floor applied on top of the mandatory checks. */
  minScore?: number;
}

export interface DenialReason {
  code: string;
  message: string;
}

export interface PostureEvaluation {
  deviceId: string;
  status: PostureStatus;
  score: number;
  passed: boolean;
  reasons: DenialReason[];
  facts: PostureFacts | null;
  evaluatedAt: string;
  reportAgeSeconds: number | null;
  edrHeartbeatAgeSeconds: number | null;
}

export interface AppPostureRequirement {
  posture?: PostureRequirements;
}

export interface AppPolicy {
  id: string;
  description?: string;
  /** Base URL of the internal application. */
  upstream: string;
  /** Host patterns (case-insensitive; `*` alone matches any host, otherwise
   *  `*` matches within a single label). At least one entry is required. */
  hosts: string[];
  /** Path prefixes. Defaults to ["/"]. */
  paths?: string[];
  allow: {
    users?: string[];
    groups?: string[];
  };
  require?: AppPostureRequirement;
  /** Optional cap on session age for this application, in minutes. */
  maxSessionMinutes?: number;
  methods?: string[];
  /** Extra headers injected into the upstream request. Cannot override X-ZTA-*. */
  injectHeaders?: Record<string, string>;
}

export interface PolicySettings {
  sessionTtlMinutes: number;
  idleTimeoutMinutes: number;
  /** How often established sessions are re-evaluated against posture. */
  postureRecheckSeconds: number;
  /** How often the proxy refreshes posture from the posture service. */
  postureCacheSeconds: number;
  /** Contract: a degraded posture must revoke a session within this window. */
  revocationSlaSeconds: number;
  /** Reject login when the device is not assigned to the authenticated user. */
  requireDeviceAssignedToUser: boolean;
  loginRateLimit: {
    maxFailures: number;
    windowSeconds: number;
    lockoutSeconds: number;
  };
}

export interface PolicyFile {
  version: 1;
  settings: PolicySettings;
  postureBaseline: PostureRequirements;
  apps: AppPolicy[];
}

export interface AuthenticatedUser {
  id: string;
  displayName: string;
  groups: string[];
  role: 'user' | 'admin';
}

export interface DeviceIdentity {
  deviceId: string;
  fingerprint256: string;
  subject: string;
  serialNumber: string;
  notAfter: string;
  sans: string[];
}

export interface SessionRecord {
  id: string;
  userId: string;
  deviceId: string;
  certFingerprint256: string;
  csrfToken: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
  sourceIp?: string;
  userAgent?: string;
  /** Applications this session has successfully accessed (for re-evaluation). */
  apps: string[];
  revokedAt?: number;
  revokeReason?: string;
  revokeReasons?: DenialReason[];
}

export interface SessionView extends SessionRecord {
  ageSeconds: number;
  idleSeconds: number;
}

export interface AccessDecision {
  allow: boolean;
  appId: string;
  reasons: DenialReason[];
  posture: PostureEvaluation;
  checks: DenialReason[];
}
