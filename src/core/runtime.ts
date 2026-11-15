/**
 * Wires the process together: database, stores, audit log, policy, posture
 * sync, session manager, revalidator, and the seed/bootstrap logic.
 *
 * `createRuntime` is the only place that knows about concrete implementations,
 * which keeps the HTTP layer testable with a runtime built in-process.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { Config } from '../config.ts';
import { loadConfig } from '../config.ts';
import { loadTrustMaterial, type TrustMaterial } from '../pki/trust.ts';
import { openDatabase, type DB } from '../store/db.ts';
import { AuditLog } from '../store/audit.ts';
import {
  DeviceStore,
  GrantStore,
  PostureStore,
  SessionStore,
  UserStore,
} from '../store/repositories.ts';
import type { DeviceRecord } from '../store/types.ts';
import { hashPassword } from '../crypto/password.ts';
import { PolicyFile, resolvePolicyPath } from '../policy/store.ts';
import { AccessController } from './access.ts';
import { SessionManager } from './sessions.ts';
import { Revalidator } from './revalidator.ts';
import { PostureSync } from '../services/posture-sync.ts';
import type { PostureReport } from '../services/posture-service.ts';
import { newId } from '../util/ids.ts';

export interface Runtime {
  config: Config;
  db: DB;
  users: UserStore;
  devices: DeviceStore;
  sessions: SessionStore;
  grants: GrantStore;
  posture: PostureStore;
  audit: AuditLog;
  policy: PolicyFile;
  access: AccessController;
  sessionManager: SessionManager;
  revalidator: Revalidator;
  trust: TrustMaterial;
  postureSync: PostureSync | null;
  logger: Logger;
  startBackground(): Promise<void>;
  shutdown(): Promise<void>;
}

export type Logger = (event: string, detail: Record<string, unknown>) => void;

export interface RuntimeOptions {
  config?: Config;
  dbPath?: string;
  pkiDir?: string;
  postureBaseUrl?: string | null;
  logger?: Logger;
  /** Skip seeding users/devices (used by tests that create their own). */
  seed?: boolean;
}

export function defaultLogger(event: string, detail: Record<string, unknown>): void {
  const line = JSON.stringify({ ts: new Date().toISOString(), event, ...detail });
  process.stdout.write(`${line}\n`);
}

export async function createRuntime(options: RuntimeOptions = {}): Promise<Runtime> {
  const config = options.config ?? loadConfig();
  if (options.dbPath !== undefined) config.dbPath = options.dbPath;
  if (options.pkiDir !== undefined) config.pkiDir = options.pkiDir;
  const logger = options.logger ?? defaultLogger;

  const db = openDatabase(config.dbPath);
  const users = new UserStore(db);
  const devices = new DeviceStore(db);
  const sessions = new SessionStore(db);
  const grants = new GrantStore(db);
  const posture = new PostureStore(db);
  const audit = new AuditLog(db, config.sessionSecret);
  const policy = new PolicyFile(resolvePolicyPath(config.configDir), config.thresholds.minOsVersion);
  const trust = loadTrustMaterial(config.pkiDir);

  const access = new AccessController({ users, devices, posture, config });
  const sessionManager = new SessionManager({ users, devices, sessions, grants, audit, config });
  const revalidator = new Revalidator({
    access,
    sessions: sessionManager,
    policy,
    audit,
    grants,
    sessionsStore: sessions,
    posture,
    config,
    logger,
  });

  if (options.seed !== false) {
    await seedUsers(users, config);
    seedDevices(devices, config);
  }

  let postureSync: PostureSync | null = null;
  const postureBaseUrl =
    options.postureBaseUrl === undefined ? `http://${config.postureService.host}:${config.postureService.port}` : options.postureBaseUrl;
  if (postureBaseUrl !== null) {
    postureSync = new PostureSync({
      baseUrl: postureBaseUrl,
      store: posture,
      // Poll a little faster than the revocation SLA demands; pushes handle
      // the urgent path, polling covers missed events and reconnect gaps.
      pollIntervalMs: Math.max(1000, Math.min(5000, config.thresholds.revalidateIntervalMs)),
      onChange: (deviceId) => revalidator.onPostureChanged(deviceId),
      logger,
    });
  }

  const runtime: Runtime = {
    config,
    db,
    users,
    devices,
    sessions,
    grants,
    posture,
    audit,
    policy,
    access,
    sessionManager,
    revalidator,
    trust,
    postureSync,
    logger,
    async startBackground() {
      revalidator.start();
      postureSync?.start(() =>
        devices
          .list()
          .filter((device) => device.status === 'enrolled')
          .map((device) => device.id),
      );
    },
    async shutdown() {
      revalidator.stop();
      postureSync?.stop();
      db.close();
    },
  };
  return runtime;
}

/** Creates demo users from config, hashing passwords lazily on first boot. */
export async function seedUsers(users: UserStore, config: Config): Promise<void> {
  if (users.count() > 0) return;
  const now = new Date().toISOString();
  for (const seed of config.seedUsers) {
    const existing = users.findByUsername(seed.username);
    if (existing !== null) continue;
    users.insert({
      id: seed.id || newId('usr'),
      username: seed.username,
      displayName: seed.displayName,
      passwordHash: await hashPassword(seed.password),
      roles: seed.roles as ('admin' | 'employee')[],
      group: seed.group,
      disabled: false,
      createdAt: now,
    });
  }
}

/**
 * Imports device certificates from the PKI manifest. Only public certificate
 * fields are recorded; private keys stay on the device.
 */
export function seedDevices(devices: DeviceStore, config: Config): void {
  const manifestPath = path.join(config.pkiDir, 'devices.json');
  if (!fs.existsSync(manifestPath)) return;
  const parsed = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
    devices?: {
      id: string;
      displayName: string;
      ownerUsername: string | null;
      group: string;
      serial: string;
      fingerprint256: string;
      issuedAt: string;
      expiresAt: string;
    }[];
  };
  if (!Array.isArray(parsed.devices)) return;
  const ownerByUsername = new Map<string, string>();
  for (const user of config.seedUsers) ownerByUsername.set(user.username, user.id);
  for (const entry of parsed.devices) {
    if (devices.findById(entry.id) !== null) continue;
    const owner = entry.ownerUsername === null ? null : (ownerByUsername.get(entry.ownerUsername) ?? null);
    const record: DeviceRecord = {
      id: entry.id,
      displayName: entry.displayName,
      ownerUserId: owner,
      group: entry.group,
      certSerial: entry.serial.toLowerCase(),
      certFingerprint256: entry.fingerprint256.toLowerCase(),
      certIssuedAt: entry.issuedAt,
      certExpiresAt: entry.expiresAt,
      status: 'enrolled',
      enrolledAt: entry.issuedAt,
      revokedAt: null,
      revokedReason: null,
      lastSeenAt: null,
    };
    devices.upsert(record);
  }
}

/** Seeds posture snapshots directly (tests, and offline demo mode). */
export function seedPostureFromManifest(posture: PostureStore, config: Config): number {
  const manifestPath = path.join(config.pkiDir, 'devices.json');
  if (!fs.existsSync(manifestPath)) return 0;
  const parsed = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
    devices?: {
      id: string;
      osName: string;
      osVersion: string;
      diskEncrypted: boolean;
      edrOnline: boolean;
      edrProduct: string;
      firewallEnabled: boolean;
      screenLockSeconds: number | null;
      patchLevel: string;
      postureAgeSeconds: number;
    }[];
  };
  if (!Array.isArray(parsed.devices)) return 0;
  const now = Date.now();
  for (const entry of parsed.devices) {
    posture.upsert({
      deviceId: entry.id,
      osName: entry.osName,
      osVersion: entry.osVersion,
      diskEncrypted: entry.diskEncrypted,
      edrOnline: entry.edrOnline,
      edrProduct: entry.edrProduct,
      firewallEnabled: entry.firewallEnabled,
      screenLockSeconds: entry.screenLockSeconds,
      patchLevel: entry.patchLevel,
      collectedAt: new Date(now - entry.postureAgeSeconds * 1000).toISOString(),
      receivedAt: new Date(now).toISOString(),
      source: 'seed',
      reportedBy: 'seeder',
    });
  }
  return parsed.devices.length;
}

/** Converts an incoming posture report into a store row (shared helper). */
export function postureSnapshotFromReport(
  report: PostureReport,
  receivedAt = new Date(),
): Parameters<PostureStore['upsert']>[0] {
  return {
    deviceId: report.deviceId,
    osName: report.osName,
    osVersion: report.osVersion,
    diskEncrypted: report.diskEncrypted,
    edrOnline: report.edrOnline,
    edrProduct: report.edrProduct,
    firewallEnabled: report.firewallEnabled,
    screenLockSeconds: report.screenLockSeconds,
    patchLevel: report.patchLevel,
    collectedAt: report.collectedAt,
    receivedAt: receivedAt.toISOString(),
    source: 'agent',
    reportedBy: 'posture-service',
  };
}

/** Re-issues a device certificate's registration (used by enrollment tooling). */
export function fingerprintOfPem(pem: string): string {
  const cert = new crypto.X509Certificate(pem);
  return cert.fingerprint256.replaceAll(':', '').toLowerCase();
}
