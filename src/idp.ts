import * as crypto from 'crypto';

interface UserRecord {
  username: string;
  salt: string;
  hash: string; // scrypt hex
}

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 32).toString('hex');
}

function makeUser(username: string, password: string): UserRecord {
  const salt = crypto.randomBytes(16).toString('hex');
  return { username, salt, hash: hashPassword(password, salt) };
}

/**
 * Local mock IdP. Stands in for the corporate IdP (OIDC/SAML) — for the demo
 * it validates username/password directly and the proxy creates the session.
 */
export class Idp {
  private users: UserRecord[];

  constructor() {
    this.users = [
      makeUser('alice', 'alice-pass'),
      makeUser('bob', 'bob-pass'),
      makeUser('carol', 'carol-pass'),
    ];
  }

  verify(username: string, password: string): boolean {
    const u = this.users.find((x) => x.username === username);
    if (!u) return false;
    const h = hashPassword(password, u.salt);
    const a = Buffer.from(h, 'hex');
    const b = Buffer.from(u.hash, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  listUsers(): string[] {
    return this.users.map((u) => u.username);
  }
}
