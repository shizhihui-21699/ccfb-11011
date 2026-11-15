import * as fs from 'fs';
import * as path from 'path';

export type AuditOutcome = 'allow' | 'deny' | 'info';

export interface AuditEvent {
  ts: string;
  kind:
    | 'login_success'
    | 'login_failure'
    | 'access_decision'
    | 'session_revoked'
    | 'session_expired'
    | 'posture_report'
    | 'mtls_rejected';
  outcome: AuditOutcome;
  user?: string;
  deviceId?: string;
  app?: string;
  reason?: string;
  ip?: string;
}

const AUDIT_FILE = path.join(__dirname, '..', 'audit.log');
const MAX_MEMORY_EVENTS = 2000;

/**
 * Append-only audit log. Every allow/deny/revoke decision is written to
 * audit.log (JSON lines) and kept in a memory ring buffer for the admin UI.
 */
export class AuditLog {
  private events: AuditEvent[] = [];

  record(e: AuditEvent): void {
    this.events.push(e);
    if (this.events.length > MAX_MEMORY_EVENTS) this.events.shift();
    fs.appendFile(AUDIT_FILE, JSON.stringify(e) + '\n', () => {});
  }

  recent(limit = 200): AuditEvent[] {
    return this.events.slice(-limit).reverse();
  }
}
