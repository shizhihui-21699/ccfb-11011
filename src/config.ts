import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  AppPolicy,
  Platform,
  PolicyFile,
  PolicySettings,
  PostureRequirements,
} from './types.ts';

export class ConfigError extends Error {
  override name = 'ConfigError';
}

export const ROOT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export interface ServiceConfig {
  host: string;
  port: number;
  certDir: string;
  dataDir: string;
  policyFile: string;
  usersFile: string;
  devicesFile: string;
  auditFile: string;
  postureServiceUrl: string;
  postureToken: string;
  upstreamTimeoutMs: number;
  tlsCaFile: string;
  tlsCertFile: string;
  tlsKeyFile: string;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value < 0) throw new ConfigError(`${name} must be a non-negative integer`);
  return value;
}

export function loadServiceConfig(): ServiceConfig {
  const certDir = resolve(process.env.ZTA_CERT_DIR ?? join(ROOT_DIR, 'certs'));
  const dataDir = resolve(process.env.ZTA_DATA_DIR ?? join(ROOT_DIR, 'data'));
  const tokenFile = resolve(process.env.ZTA_POSTURE_TOKEN_FILE ?? join(dataDir, 'posture-token.txt'));
  let postureToken = process.env.ZTA_POSTURE_TOKEN ?? '';
  if (!postureToken) {
    try {
      postureToken = readFileSync(tokenFile, 'utf8').trim();
    } catch {
      throw new ConfigError(
        `Posture service token is missing. Run "npm run setup" or set ZTA_POSTURE_TOKEN (expected file: ${tokenFile}).`,
      );
    }
  }
  if (postureToken.length < 16) throw new ConfigError('Posture service token must be at least 16 characters');

  return {
    host: process.env.ZTA_HOST ?? '127.0.0.1',
    port: envInt('ZTA_PORT', 8443),
    certDir,
    dataDir,
    policyFile: resolve(process.env.ZTA_POLICY_FILE ?? join(ROOT_DIR, 'config', 'policy.json')),
    usersFile: resolve(process.env.ZTA_USERS_FILE ?? join(dataDir, 'users.json')),
    devicesFile: resolve(process.env.ZTA_DEVICES_FILE ?? join(dataDir, 'devices.json')),
    auditFile: resolve(process.env.ZTA_AUDIT_FILE ?? join(dataDir, 'audit.jsonl')),
    postureServiceUrl: (process.env.ZTA_POSTURE_URL ?? 'http://127.0.0.1:8450').replace(/\/+$/, ''),
    postureToken,
    upstreamTimeoutMs: envInt('ZTA_UPSTREAM_TIMEOUT_MS', 15_000),
    tlsCaFile: resolve(process.env.ZTA_TLS_CA ?? join(certDir, 'ca.crt')),
    tlsCertFile: resolve(process.env.ZTA_TLS_CERT ?? join(certDir, 'server.crt')),
    tlsKeyFile: resolve(process.env.ZTA_TLS_KEY ?? join(certDir, 'server.key')),
  };
}

const PLATFORMS: Platform[] = ['darwin', 'win32', 'linux'];

function fail(path: string, message: string): never {
  throw new ConfigError(`policy ${path}: ${message}`);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function num(value: unknown, path: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) {
    fail(path, `expected a number between ${min} and ${max}`);
  }
  return value;
}

function str(value: unknown, path: string): string {
  if (typeof value !== 'string' || !value.trim()) fail(path, 'expected a non-empty string');
  return value.trim();
}

function optionalStrArray(value: unknown, path: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string' || !v.trim())) {
    fail(path, 'expected an array of non-empty strings');
  }
  return (value as string[]).map((v) => v.trim());
}

function validatePostureRequirements(value: unknown, path: string): PostureRequirements {
  if (value === undefined) return {};
  if (!isObject(value)) fail(path, 'expected an object');
  const out: PostureRequirements = {};
  if (value.minOsVersion !== undefined) {
    if (!isObject(value.minOsVersion)) fail(`${path}.minOsVersion`, 'expected an object');
    out.minOsVersion = {};
    for (const [key, version] of Object.entries(value.minOsVersion)) {
      if (!PLATFORMS.includes(key as Platform)) {
        fail(`${path}.minOsVersion.${key}`, `unknown platform (expected ${PLATFORMS.join(', ')})`);
      }
      out.minOsVersion[key as Platform] = str(version, `${path}.minOsVersion.${key}`);
    }
  }
  for (const key of ['requireDiskEncryption', 'requireEdrInstalled', 'requireEdrRunning'] as const) {
    if (value[key] !== undefined) {
      if (typeof value[key] !== 'boolean') fail(`${path}.${key}`, 'expected a boolean');
      out[key] = value[key] as boolean;
    }
  }
  for (const key of ['maxEdrHeartbeatAgeSeconds', 'maxReportAgeSeconds', 'minScore'] as const) {
    if (value[key] !== undefined) out[key] = num(value[key], `${path}.${key}`, 0, 100_000);
  }
  return out;
}

function validateSettings(value: unknown): PolicySettings {
  if (!isObject(value)) fail('settings', 'expected an object');
  const rate = isObject(value.loginRateLimit) ? value.loginRateLimit : {};
  return {
    sessionTtlMinutes: num(value.sessionTtlMinutes ?? 480, 'settings.sessionTtlMinutes', 1, 43_200),
    idleTimeoutMinutes: num(value.idleTimeoutMinutes ?? 30, 'settings.idleTimeoutMinutes', 1, 43_200),
    postureRecheckSeconds: num(value.postureRecheckSeconds ?? 5, 'settings.postureRecheckSeconds', 0.05, 3_600),
    postureCacheSeconds: num(value.postureCacheSeconds ?? 2, 'settings.postureCacheSeconds', 0.05, 3_600),
    revocationSlaSeconds: num(value.revocationSlaSeconds ?? 60, 'settings.revocationSlaSeconds', 1, 3_600),
    requireDeviceAssignedToUser: value.requireDeviceAssignedToUser !== false,
    loginRateLimit: {
      maxFailures: num(rate.maxFailures ?? 5, 'settings.loginRateLimit.maxFailures', 1, 1_000),
      windowSeconds: num(rate.windowSeconds ?? 300, 'settings.loginRateLimit.windowSeconds', 1, 86_400),
      lockoutSeconds: num(rate.lockoutSeconds ?? 300, 'settings.loginRateLimit.lockoutSeconds', 1, 86_400),
    },
  };
}

function validateApp(value: unknown, index: number): AppPolicy {
  const path = `apps[${index}]`;
  if (!isObject(value)) fail(path, 'expected an object');
  const id = str(value.id, `${path}.id`);
  if (!/^[a-z0-9][a-z0-9-_]{0,63}$/.test(id)) fail(`${path}.id`, 'use lowercase letters, digits, "-" or "_"');
  const upstream = str(value.upstream, `${path}.upstream`);
  let upstreamUrl: URL;
  try {
    upstreamUrl = new URL(upstream);
  } catch {
    fail(`${path}.upstream`, 'expected a valid URL');
  }
  if (!['http:', 'https:'].includes(upstreamUrl.protocol)) fail(`${path}.upstream`, 'only http(s) upstreams are supported');

  if (!Array.isArray(value.hosts) || value.hosts.length === 0) {
    fail(`${path}.hosts`, 'expected a non-empty array (use ["*"] to match any host)');
  }
  const hosts = value.hosts.map((h, i) => str(h, `${path}.hosts[${i}]`).toLowerCase());

  const allow = isObject(value.allow) ? value.allow : fail(`${path}.allow`, 'expected an object');
  const allowUsers = optionalStrArray(allow.users, `${path}.allow.users`);
  const allowGroups = optionalStrArray(allow.groups, `${path}.allow.groups`);
  if (!allowUsers?.length && !allowGroups?.length) {
    fail(`${path}.allow`, 'must list at least one user or group');
  }

  const require = isObject(value.require) ? value.require : {};
  const methods = optionalStrArray(value.methods, `${path}.methods`)?.map((m) => m.toUpperCase());
  let injectHeaders: Record<string, string> | undefined;
  if (value.injectHeaders !== undefined) {
    if (!isObject(value.injectHeaders)) fail(`${path}.injectHeaders`, 'expected an object');
    injectHeaders = {};
    for (const [key, headerValue] of Object.entries(value.injectHeaders)) {
      if (/^x-zta-/i.test(key) || /[\r\n]/.test(key) || typeof headerValue !== 'string' || /[\r\n]/.test(headerValue)) {
        fail(`${path}.injectHeaders.${key}`, 'invalid header name/value (X-ZTA-* is reserved)');
      }
      injectHeaders[key] = headerValue;
    }
  }

  return {
    id,
    description: value.description === undefined ? undefined : str(value.description, `${path}.description`),
    upstream,
    hosts,
    paths: optionalStrArray(value.paths, `${path}.paths`) ?? ['/'],
    allow: { users: allowUsers, groups: allowGroups },
    require: { posture: validatePostureRequirements(require.posture, `${path}.require.posture`) },
    maxSessionMinutes:
      value.maxSessionMinutes === undefined
        ? undefined
        : num(value.maxSessionMinutes, `${path}.maxSessionMinutes`, 1, 43_200),
    methods,
    injectHeaders,
  };
}

export function validatePolicy(raw: unknown): PolicyFile {
  if (!isObject(raw)) fail('root', 'expected an object');
  if (raw.version !== 1) fail('version', 'expected 1');
  if (!Array.isArray(raw.apps) || raw.apps.length === 0) fail('apps', 'expected a non-empty array');
  const apps = raw.apps.map(validateApp);
  const ids = new Set<string>();
  for (const app of apps) {
    if (ids.has(app.id)) fail('apps', `duplicate app id "${app.id}"`);
    ids.add(app.id);
  }
  // An app with no path prefixes would silently match nothing; catch it here
  // instead of leaving an unreachable policy in place.
  for (const app of apps) {
    if (!app.paths || app.paths.length === 0) fail(`apps[${app.id}].paths`, 'expected at least one path prefix');
  }
  const settings = validateSettings(raw.settings ?? {});
  if (settings.postureRecheckSeconds >= settings.revocationSlaSeconds) {
    fail('settings.revocationSlaSeconds', 'must be greater than settings.postureRecheckSeconds');
  }
  return {
    version: 1,
    settings,
    postureBaseline: validatePostureRequirements(raw.postureBaseline ?? {}, 'postureBaseline'),
    apps,
  };
}

export function loadPolicy(path: string = join(ROOT_DIR, 'config', 'policy.json')): PolicyFile {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    throw new ConfigError(`Cannot read policy file ${path}: ${(error as Error).message}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new ConfigError(`Policy file ${path} is not valid JSON: ${(error as Error).message}`);
  }
  return validatePolicy(raw);
}

/** Merge a per-app requirement over the baseline; app values win field by field. */
export function mergePostureRequirements(
  base: PostureRequirements,
  override: PostureRequirements | undefined,
): PostureRequirements {
  if (!override) return { ...base, minOsVersion: base.minOsVersion ? { ...base.minOsVersion } : undefined };
  return {
    minOsVersion: { ...(base.minOsVersion ?? {}), ...(override.minOsVersion ?? {}) },
    requireDiskEncryption: override.requireDiskEncryption ?? base.requireDiskEncryption,
    requireEdrInstalled: override.requireEdrInstalled ?? base.requireEdrInstalled,
    requireEdrRunning: override.requireEdrRunning ?? base.requireEdrRunning,
    maxEdrHeartbeatAgeSeconds: override.maxEdrHeartbeatAgeSeconds ?? base.maxEdrHeartbeatAgeSeconds,
    maxReportAgeSeconds: override.maxReportAgeSeconds ?? base.maxReportAgeSeconds,
    minScore: override.minScore ?? base.minScore,
  };
}
