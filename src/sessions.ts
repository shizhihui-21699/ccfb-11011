import * as crypto from 'crypto';

export interface Session {
  id: string;
  user: string;
  deviceId: string;
  createdAt: number;
  /** apps this session has been allowed into — re-evaluated by the posture monitor */
  grantedApps: Set<string>;
}

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8h absolute cap

export class SessionStore {
  private sessions = new Map<string, Session>();
  private hmacKey = crypto.randomBytes(32);

  create(user: string, deviceId: string): Session {
    const id = crypto.randomBytes(24).toString('base64url');
    const s: Session = { id, user, deviceId, createdAt: Date.now(), grantedApps: new Set() };
    this.sessions.set(id, s);
    return s;
  }

  /** Signed cookie value: <id>.<hmac> */
  cookieFor(s: Session): string {
    const sig = crypto.createHmac('sha256', this.hmacKey).update(s.id).digest('base64url');
    return `${s.id}.${sig}`;
  }

  getByCookie(cookie: string | undefined): Session | null {
    if (!cookie) return null;
    const dot = cookie.lastIndexOf('.');
    if (dot <= 0) return null;
    const id = cookie.slice(0, dot);
    const sig = cookie.slice(dot + 1);
    const expect = crypto.createHmac('sha256', this.hmacKey).update(id).digest('base64url');
    const a = Buffer.from(sig);
    const b = Buffer.from(expect);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const s = this.sessions.get(id) ?? null;
    if (s && Date.now() - s.createdAt > SESSION_TTL_MS) {
      this.sessions.delete(id);
      return null;
    }
    return s;
  }

  revoke(id: string): Session | null {
    const s = this.sessions.get(id) ?? null;
    this.sessions.delete(id);
    return s;
  }

  list(): Session[] {
    return [...this.sessions.values()];
  }
}
