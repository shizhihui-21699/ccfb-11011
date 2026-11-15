/**
 * Local user directory. In production this would be an OIDC/SAML IdP; the
 * proxy only depends on the `AuthenticatedUser` shape, so swapping the
 * verifier does not touch the policy engine.
 */
import { existsSync, readFileSync } from 'node:fs';
import type { AuthenticatedUser, UserDirectoryFile, UserRecord } from '../types.ts';
import type { Logger } from '../log.ts';
import { verifyPassword } from '../password.ts';

export class UserStoreError extends Error {
  override name = 'UserStoreError';
}

export interface LoginResult {
  ok: boolean;
  user?: AuthenticatedUser;
  reason?: 'unknown_user' | 'bad_password' | 'disabled';
}

export class UserStore {
  private readonly filePath: string;
  private readonly log: Logger;
  private users = new Map<string, UserRecord>();
  private loaded = false;

  constructor(filePath: string, log: Logger) {
    this.filePath = filePath;
    this.log = log;
  }

  private ensureLoaded(): void {
    if (this.loaded) return;
    this.users.clear();
    if (!existsSync(this.filePath)) {
      throw new UserStoreError(`user directory not found: ${this.filePath} (run "npm run setup")`);
    }
    const raw = JSON.parse(readFileSync(this.filePath, 'utf8')) as UserDirectoryFile;
    if (raw.version !== 1 || !Array.isArray(raw.users)) {
      throw new UserStoreError(`${this.filePath}: unsupported user directory format`);
    }
    for (const user of raw.users) {
      if (!/^[a-z0-9][a-z0-9._-]{1,63}$/.test(user.id)) {
        this.log.warn('skipping user with invalid id', { id: user.id });
        continue;
      }
      this.users.set(user.id, user);
    }
    this.loaded = true;
  }

  /** Verify a user id + password. Failure reasons are intentionally coarse to the caller. */
  authenticate(userId: string, password: string): LoginResult {
    this.ensureLoaded();
    const record = this.users.get(userId);
    if (!record) {
      // Perform a dummy scrypt anyway to keep timing comparable.
      verifyPassword(password, 'scrypt$16384$8$1$00$' + '00'.repeat(64));
      return { ok: false, reason: 'unknown_user' };
    }
    if (!verifyPassword(password, record.passwordHash)) {
      return { ok: false, reason: 'bad_password' };
    }
    return {
      ok: true,
      user: {
        id: record.id,
        displayName: record.displayName,
        groups: [...record.groups],
        role: record.role,
      },
    };
  }

  get(userId: string): AuthenticatedUser | undefined {
    this.ensureLoaded();
    const record = this.users.get(userId);
    if (!record) return undefined;
    return { id: record.id, displayName: record.displayName, groups: [...record.groups], role: record.role };
  }

  list(): AuthenticatedUser[] {
    this.ensureLoaded();
    return [...this.users.values()]
      .map((u) => ({ id: u.id, displayName: u.displayName, groups: [...u.groups], role: u.role }))
      .sort((a, b) => a.id.localeCompare(b.id));
  }
}
