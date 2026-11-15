import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import * as http from 'http';
import express from 'express';
import { CERTS_DIR, deviceIdFromPeerCert } from './ca';
import { AuditLog } from './audit';
import { SessionStore } from './sessions';
import { Idp } from './idp';
import { evaluate, loadPolicies, PolicyConfig } from './policy';
import { fetchPosture } from './posture';

export const PROXY_PORT = 8443;
/** Posture re-evaluation cadence — worst-case revocation latency is this + fetch time. */
const MONITOR_INTERVAL_MS = 10_000;

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

const loginPage = (deviceId: string, error = '') => `<!doctype html>
<html><head><title>ZTNA Login</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui;max-width:24rem;margin:4rem auto;padding:0 1rem}
input,button{width:100%;padding:.5rem;margin:.25rem 0;box-sizing:border-box}
.err{color:#b00}</style></head><body>
<h2>Zero-Trust Access</h2>
<p>Device certificate verified: <code>${deviceId}</code></p>
${error ? `<p class="err">${error}</p>` : ''}
<form method="post" action="/login">
<input name="username" placeholder="username" autocomplete="username">
<input name="password" type="password" placeholder="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form>
<p><small>demo users: alice / bob / carol (password: &lt;name&gt;-pass)</small></p>
</body></html>`;

export function startProxy(audit: AuditLog, sessions: SessionStore, idp: Idp): void {
  const policies: PolicyConfig = loadPolicies();

  const app = express();
  app.use(express.urlencoded({ extended: false }));

  // --- device identity from the mTLS client certificate ---
  app.use((req, res, next) => {
    const sock = req.socket as import('tls').TLSSocket;
    const cert = sock.getPeerCertificate();
    const deviceId = deviceIdFromPeerCert(cert);
    if (!deviceId) {
      audit.record({
        ts: new Date().toISOString(),
        kind: 'mtls_rejected',
        outcome: 'deny',
        reason: 'client certificate has no device ID',
        ip: req.socket.remoteAddress,
      });
      res.status(403).send('client certificate has no device identity');
      return;
    }
    res.locals.deviceId = deviceId;
    next();
  });

  app.get('/', (req, res) => {
    const session = sessions.getByCookie(parseCookies(req.headers.cookie).ztna);
    const appLinks = Object.keys(policies.apps)
      .map((n) => `<li><a href="/app/${n}/">${n}</a></li>`)
      .join('');
    res.send(`<!doctype html><html><head><title>ZTNA</title></head><body>
<h2>Zero-Trust Access Proxy</h2>
<p>device: <code>${res.locals.deviceId}</code>${
      session ? ` · signed in as <b>${session.user}</b>` : ' · <a href="/login">sign in</a>'
    }</p>
<ul>${appLinks}</ul>
</body></html>`);
  });

  app.get('/login', (_req, res) => {
    res.send(loginPage(res.locals.deviceId));
  });

  app.post('/login', (req, res) => {
    const { username = '', password = '' } = req.body ?? {};
    const deviceId = res.locals.deviceId as string;
    if (!idp.verify(username, password)) {
      audit.record({
        ts: new Date().toISOString(),
        kind: 'login_failure',
        outcome: 'deny',
        user: username,
        deviceId,
        reason: 'bad credentials',
        ip: req.socket.remoteAddress,
      });
      res.status(401).send(loginPage(deviceId, 'invalid username or password'));
      return;
    }
    const session = sessions.create(username, deviceId);
    audit.record({
      ts: new Date().toISOString(),
      kind: 'login_success',
      outcome: 'allow',
      user: username,
      deviceId,
      ip: req.socket.remoteAddress,
    });
    res.setHeader(
      'Set-Cookie',
      `ztna=${sessions.cookieFor(session)}; HttpOnly; Secure; SameSite=Lax; Path=/`,
    );
    res.redirect('/');
  });

  app.post('/logout', (req, res) => {
    const session = sessions.getByCookie(parseCookies(req.headers.cookie).ztna);
    if (session) sessions.revoke(session.id);
    res.setHeader('Set-Cookie', 'ztna=; HttpOnly; Secure; Path=/; Max-Age=0');
    res.redirect('/');
  });

  // --- per-app policy enforcement + reverse proxy ---
  app.use('/app/:appName', async (req, res) => {
    const appName = req.params.appName;
    const policy = policies.apps[appName];
    const deviceId = res.locals.deviceId as string;
    if (!policy) {
      res.status(404).send(`unknown app: ${appName}`);
      return;
    }
    const session = sessions.getByCookie(parseCookies(req.headers.cookie).ztna);
    if (!session) {
      res.redirect('/login');
      return;
    }
    if (session.deviceId !== deviceId) {
      // cookie presented from a different device than it was issued on
      audit.record({
        ts: new Date().toISOString(),
        kind: 'access_decision',
        outcome: 'deny',
        user: session.user,
        deviceId,
        app: appName,
        reason: `session bound to device ${session.deviceId}`,
        ip: req.socket.remoteAddress,
      });
      res.status(403).send('session is bound to a different device');
      return;
    }

    const posture = await fetchPosture(deviceId);
    const decision = evaluate(policy, session.user, posture);
    audit.record({
      ts: new Date().toISOString(),
      kind: 'access_decision',
      outcome: decision.allow ? 'allow' : 'deny',
      user: session.user,
      deviceId,
      app: appName,
      reason: decision.allow ? 'policy satisfied' : decision.reasons.join('; '),
      ip: req.socket.remoteAddress,
    });
    if (!decision.allow) {
      res
        .status(403)
        .send(
          `<h2>Access denied by policy</h2><ul>${decision.reasons
            .map((r) => `<li>${r}</li>`)
            .join('')}</ul>`,
        );
      return;
    }

    session.grantedApps.add(appName);

    // forward to the upstream app
    const upstream = new URL(policy.upstream);
    const proxyReq = http.request(
      {
        hostname: upstream.hostname,
        port: upstream.port,
        path: req.url,
        method: req.method,
        headers: {
          ...req.headers,
          host: upstream.host,
          'x-ztna-user': session.user,
          'x-ztna-device': deviceId,
        },
      },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
        proxyRes.pipe(res);
      },
    );
    proxyReq.on('error', () => res.status(502).send('upstream unavailable'));
    req.pipe(proxyReq);
  });

  // --- continuous evaluation: revoke sessions whose device posture degrades ---
  setInterval(() => {
    void (async () => {
      for (const s of sessions.list()) {
        if (s.grantedApps.size === 0) continue;
        const posture = await fetchPosture(s.deviceId);
        for (const appName of s.grantedApps) {
          const policy = policies.apps[appName];
          if (!policy) continue;
          const d = evaluate(policy, s.user, posture);
          if (!d.allow) {
            sessions.revoke(s.id);
            audit.record({
              ts: new Date().toISOString(),
              kind: 'session_revoked',
              outcome: 'deny',
              user: s.user,
              deviceId: s.deviceId,
              app: appName,
              reason: `posture no longer satisfies policy: ${d.reasons.join('; ')}`,
            });
            break;
          }
        }
      }
    })();
  }, MONITOR_INTERVAL_MS);

  const tlsOptions: https.ServerOptions = {
    cert: fs.readFileSync(path.join(CERTS_DIR, 'server.crt.pem')),
    key: fs.readFileSync(path.join(CERTS_DIR, 'server.key.pem')),
    ca: fs.readFileSync(path.join(CERTS_DIR, 'ca.crt.pem')),
    requestCert: true,
    rejectUnauthorized: true, // only CA-issued device certs can complete the handshake
  };

  https.createServer(tlsOptions, app).listen(PROXY_PORT, () => {
    console.log(`[proxy] mTLS zero-trust proxy on https://localhost:${PROXY_PORT}`);
  });
}
