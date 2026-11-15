/**
 * Configuration is loaded from environment variables, with a JSON file
 * overlay for policy/application definitions. Nothing here is secret unless
 * you put it in the env — all trust material lives on disk under `pki/`.
 */
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export interface AppDefinition {
  /** Stable application id referenced by policy rules and sessions. */
  id: string;
  name: string;
  description?: string;
  /** Upstream origin the proxy relays to, e.g. http://127.0.0.1:9101 */
  upstream: string;
  /** Optional human-facing host/path hint shown in the admin console. */
  pathHint?: string;
}

export interface Thresholds {
  /** Posture older than this is treated as stale and fails closed. */
  postureMaxAgeSeconds: number;
  /**
   * Minimum OS version per family — version schemes are not comparable across
   * macOS, Windows and Linux, so a single global string is not used.
   */
  minOsVersion: import('./util/version.ts').VersionFloor;
  /** How often live sessions re-evaluate posture, in milliseconds. */
  revalidateIntervalMs: number;
  /** Hard upper bound for revoking a live session after a posture downgrade. */
  revokeWithinMs: number;
}

export interface Config {
  host: string;
  port: number;
  /** Public origin used in links and redirects. */
  publicOrigin: string;
  /** Directory holding the CA, server cert/key, and per-device material. */
  pkiDir: string;
  /** Directory the JSON config file was loaded from (for policy lookup). */
  configDir: string;
  /** SQLite file for users, devices, sessions, posture and audit. */
  dbPath: string;
  /** 32-byte base64 key used to seal session cookies. */
  sessionSecret: string;
  /** How long a session cookie stays valid before re-authentication. */
  sessionTtlSeconds: number;
  /** How long a signed-in user's device grant survives without re-check. */
  grantTtlSeconds: number;
  thresholds: Thresholds;
  apps: AppDefinition[];
  /** Seed identities used the first time the database is created. */
  seedUsers: SeedUser[];
  /** Bind address for the simulated local posture service. */
  postureService: { host: string; port: number };
  /** Whether the proxy trusts X-Forwarded-For (only for a fronting LB). */
  trustProxy: boolean;
}

export interface SeedUser {
  id: string;
  username: string;
  displayName: string;
  password: string;
  roles: string[];
  group: string;
}

const DEFAULTS = {
  host: '127.0.0.1',
  port: 8443,
  postureHost: '127.0.0.1',
  posturePort: 9200,
};

export function loadConfig(env: NodeJS.ProcessEnv = process.env, root = process.cwd()): Config {
  const configPath = env.ZT_CONFIG ?? path.join(root, 'config', 'zero-trust.json');
  const raw = fs.existsSync(configPath)
    ? (JSON.parse(fs.readFileSync(configPath, 'utf8')) as Partial<Config>)
    : {};

  const pkiDir = path.resolve(root, env.ZT_PKI_DIR ?? raw.pkiDir ?? 'pki');
  const dbPath = path.resolve(root, env.ZT_DB_PATH ?? raw.dbPath ?? '.zt/zero-trust.db');

  const apps = raw.apps ?? [];
  if (apps.length === 0) {
    throw new ConfigError(
      `no applications configured; define "apps" in ${configPath} or set ZT_CONFIG`,
    );
  }
  for (const app of apps) {
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(app.id)) {
      throw new ConfigError(`invalid application id "${app.id}" (use lowercase kebab-case)`);
    }
  }

  const sessionSecret = resolveSessionSecret(env, raw.sessionSecret, dbPath);

  return {
    host: env.ZT_HOST ?? raw.host ?? DEFAULTS.host,
    port: Number(env.ZT_PORT ?? raw.port ?? DEFAULTS.port),
    publicOrigin: env.ZT_PUBLIC_ORIGIN ?? raw.publicOrigin ?? `https://${DEFAULTS.host}:${env.ZT_PORT ?? raw.port ?? DEFAULTS.port}`,
    pkiDir,
    configDir: path.dirname(configPath),
    dbPath,
    sessionSecret,
    sessionTtlSeconds: Number(env.ZT_SESSION_TTL ?? raw.sessionTtlSeconds ?? 8 * 3600),
    grantTtlSeconds: Number(env.ZT_GRANT_TTL ?? raw.grantTtlSeconds ?? 12 * 3600),
    thresholds: {
      postureMaxAgeSeconds: Number(raw.thresholds?.postureMaxAgeSeconds ?? 180),
      minOsVersion: raw.thresholds?.minOsVersion ?? '14.0.0',
      revalidateIntervalMs: Number(raw.thresholds?.revalidateIntervalMs ?? 10_000),
      revokeWithinMs: Number(raw.thresholds?.revokeWithinMs ?? 60_000),
    },
    apps,
    seedUsers: raw.seedUsers ?? [],
    postureService: {
      host: env.ZT_POSTURE_HOST ?? DEFAULTS.postureHost,
      port: Number(env.ZT_POSTURE_PORT ?? DEFAULTS.posturePort),
    },
    trustProxy: env.ZT_TRUST_PROXY === '1' || raw.trustProxy === true,
  };
}

export class ConfigError extends Error {
  override name = 'ConfigError';
}

/**
 * Session secret resolution. Precedence: explicit env/JSON value, then a
 * generated secret persisted next to the database (mode 0600) so restarts do
 * not invalidate every cookie. A generated secret is logged once, loudly, so
 * production deployments know to set ZT_SESSION_SECRET explicitly.
 */
function resolveSessionSecret(
  env: NodeJS.ProcessEnv,
  configured: string | undefined,
  dbPath: string,
): string {
  const explicit = env.ZT_SESSION_SECRET ?? configured;
  if (typeof explicit === 'string' && explicit.length >= 16) return explicit;
  if (explicit !== undefined && explicit !== '') {
    throw new ConfigError('ZT_SESSION_SECRET must be at least 16 characters');
  }
  const secretFile = path.join(path.dirname(dbPath), 'session-secret');
  try {
    const existing = fs.readFileSync(secretFile, 'utf8').trim();
    if (existing.length >= 16) return existing;
  } catch {
    // fall through and generate
  }
  const generated = randomBytes(32).toString('base64');
  try {
    fs.mkdirSync(path.dirname(secretFile), { recursive: true, mode: 0o700 });
    fs.writeFileSync(secretFile, `${generated}\n`, { mode: 0o600 });
    fs.chmodSync(secretFile, 0o600);
    process.stderr.write(
      `[config] ZT_SESSION_SECRET not set; generated one at ${secretFile} (dev convenience). ` +
        'Set ZT_SESSION_SECRET explicitly in production.\n',
    );
  } catch {
    process.stderr.write('[config] ZT_SESSION_SECRET not set and could not be persisted; using an ephemeral secret.\n');
  }
  return generated;
}

/** Validates the shape of an app config entry loaded from JSON. */
export function assertValidApps(apps: AppDefinition[]): void {
  const seen = new Set<string>();
  for (const app of apps) {
    if (seen.has(app.id)) throw new ConfigError(`duplicate application id "${app.id}"`);
    seen.add(app.id);
    let url: URL;
    try {
      url = new URL(app.upstream);
    } catch {
      throw new ConfigError(`application "${app.id}" has an invalid upstream URL`);
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new ConfigError(`application "${app.id}" upstream must be http(s)`);
    }
  }
}
