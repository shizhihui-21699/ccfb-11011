import { AuditLog } from './audit';
import { SessionStore } from './sessions';
import { Idp } from './idp';
import { startPostureService } from './posture';
import { startBackends } from './backends';
import { startProxy } from './proxy';
import { startAdmin } from './admin';

const audit = new AuditLog();
const sessions = new SessionStore();
const idp = new Idp();

startBackends();
startPostureService(audit);
startProxy(audit, sessions, idp);
startAdmin(audit, sessions);
