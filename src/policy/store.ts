/**
 * Policy documents live in `config/policy.json` and are hot-reloadable. The
 * file is validated in full before it replaces the in-memory document; a bad
 * edit is rejected and the previous policy stays in force.
 */
import fs from 'node:fs';
import path from 'node:path';
import { normalizePolicy, PolicyError, type PolicyDocument } from './engine.ts';
import type { VersionFloor } from '../util/version.ts';

export interface PolicySource {
  current: PolicyDocument;
  updatedAt: Date;
  fingerprint: string;
  loadError: string | null;
}

export class PolicyFile {
  private source: PolicySource;

  private readonly filePath: string;
  private readonly defaultMinOsVersion: VersionFloor | undefined;

  constructor(filePath: string, defaultMinOsVersion: VersionFloor | undefined) {
    this.filePath = filePath;
    this.defaultMinOsVersion = defaultMinOsVersion;
    this.source = this.read();
  }

  get(): PolicySource {
    return this.source;
  }

  /** Re-reads the file if its mtime/size changed. Returns true on success. */
  reloadIfChanged(): boolean {
    const stat = safeStat(this.filePath);
    if (stat === null) return false;
    const fingerprint = `${stat.mtimeMs}:${stat.size}`;
    if (fingerprint === this.source.fingerprint) return false;
    try {
      this.source = this.read();
      return true;
    } catch (error) {
      this.source = {
        ...this.source,
        fingerprint,
        loadError: error instanceof Error ? error.message : String(error),
      };
      return false;
    }
  }

  private read(): PolicySource {
    const stat = safeStat(this.filePath);
    if (stat === null) {
      throw new PolicyError(`policy file not found: ${this.filePath}`);
    }
    const raw = fs.readFileSync(this.filePath, 'utf8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new PolicyError(`policy file is not valid JSON: ${this.filePath}`);
    }
    const document = normalizePolicy(parsed, this.defaultMinOsVersion);
    return {
      current: document,
      updatedAt: stat.mtime,
      fingerprint: `${stat.mtimeMs}:${stat.size}`,
      loadError: null,
    };
  }
}

function safeStat(filePath: string): fs.Stats | null {
  try {
    return fs.statSync(filePath);
  } catch {
    return null;
  }
}

/** Resolves `config/policy.json` next to the main config unless overridden. */
export function resolvePolicyPath(configRoot: string, env: NodeJS.ProcessEnv = process.env): string {
  return env.ZT_POLICY ?? path.join(configRoot, 'policy.json');
}
