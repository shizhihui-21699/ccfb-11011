/**
 * End-to-end HTTP tests over real TLS with real client certificates.
 *
 * Each test builds its own PKI, posture service, mock upstream and proxy, so
 * the assertions exercise the same code path a browser would.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import http from 'node:http';
import { after, before, test } from 'node:test';
import type { AddressInfo } from 'node:net';
import { loadConfig } from '../src/config.ts';
import { createRuntime, type Runtime } from '../src/core/runtime.ts';
import { startServer, type ServerHandle } from '../src/http/server.ts';
import { PostureService } from '../src/services/posture-service.ts';
import { buildTestPki, writeTestConfig, type TestPki } from './helpers/pki.ts';

const FLOOR = { macos: '14.0.0', windows: '10.0.19045', linux: '5.15.0' };

interface Env {
  pki: TestPki;
  runtime: Runtime;
  server: ServerHandle;
  posture: PostureService;
  upstream: http.Server;
  upstreamPort: number;
  close(): Promise<void>;
}

interface FetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  device?: 'alpha' | 'beta' | 'none';
  cookie?: string;
}

interface FetchResult {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

const RUN = `it-${process.pid}-${Math.floor(Math.random() * 1e6)}`;

async function buildEnv(): Promise<Env> {
  const pki = buildTestPki([
    { id: 'dev-alpha', owner: 'admin', group: 'laptop' },
    { id: 'dev-beta', owner: 'emp', group: 'laptop' },
  ]);
  const { configPath } = writeTestConfig(
    pki,
    {
      thresholds: { postureMaxAgeSeconds: 180, minOsVersion: FLOOR, revalidateIntervalMs: 200, revokeWithinMs: 60_000 },
      apps: [
        { id: 'wiki', name: 'Wiki', upstream: 'http://127.0.0.1:1' },
        { id: 'payroll', name: 'Payroll', upstream: 'http://127.0.0.1:1' },
        { id: 'ops', name: 'Ops', upstream: 'http://127.0.0.1:1' },
      ],
    },
    {
      version: 1,
      rules: [
        {
          id: 'ops-engineering',
          effect: 'allow',
          apps: ['ops'],
          groups: ['engineering'],
          requireEdrOnline: true,
        },
        { id: 'payroll-finance', effect: 'allow', apps: ['payroll'], groups: ['finance'], requireDiskEncrypted: true },
        { id: 'wiki-all', effect: 'allow', apps: ['wiki'], roles: ['employee', 'admin'] },
      ],
    },
  );
  const config = loadConfig({ ZT_CONFIG: configPath }, '/tmp');

  const upstream = http.createServer((req, res) => {
    const payload = JSON.stringify({
      path: req.url,
      user: req.headers['x-zt-user-id'],
      device: req.headers['x-zt-device-id'],
      cookie: req.headers['cookie'] ?? null,
      authorization: req.headers['authorization'] ?? null,
    });
    if (req.url === '/redirect-me') {
      res.writeHead(302, { location: '/landed' });
      res.end();
      return;
    }
    if (req.url === '/cookie') {
      res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'up=1; Path=/' });
      res.end(payload);
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(payload);
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', () => resolve()));
  const upstreamPort = (upstream.address() as AddressInfo).port;

  const posture = new PostureService({ port: 0 });
  const posturePort = await posture.start();
  const runtime = await createRuntime({
    config,
    postureBaseUrl: `http://127.0.0.1:${posturePort}`,
    logger: () => {},
  });
  // Point every app at the live mock upstream.
  for (const app of runtime.config.apps) app.upstream = `http://127.0.0.1:${upstreamPort}`;

  for (const device of pki.devices) {
    runtime.devices.upsert({
      id: device.id,
      displayName: device.id,
      ownerUserId: device.ownerUsername === 'admin' ? 'usr_admin' : device.ownerUsername === 'emp' ? 'usr_emp' : null,
      group: device.group,
      certSerial: device.serial,
      certFingerprint256: device.fingerprint256,
      certIssuedAt: new Date().toISOString(),
      certExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      status: 'enrolled',
      enrolledAt: new Date().toISOString(),
      revokedAt: null,
      revokedReason: null,
      lastSeenAt: null,
    });
    posture.put({
      deviceId: device.id,
      osName: device.id === 'dev-beta' ? 'Windows' : 'macOS',
      osVersion: device.id === 'dev-beta' ? '11.0.22631' : '15.2.0',
      diskEncrypted: true,
      edrOnline: true,
      edrProduct: 'Falcon',
      firewallEnabled: true,
      screenLockSeconds: 300,
      patchLevel: '2026-01',
      collectedAt: new Date().toISOString(),
    });
  }
  await runtime.postureSync!.poll(['dev-alpha', 'dev-beta']);

  const server = await startServer({ runtime, port: 0, pkiDir: pki.dir });
  return {
    pki,
    runtime,
    server,
    posture,
    upstream,
    upstreamPort,
    async close() {
      await server.close();
      await posture.stop();
      await runtime.shutdown();
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    },
  };
}

function certFor(env: Env, which: 'alpha' | 'beta'): { cert: Buffer; key: Buffer } {
  const id = which === 'alpha' ? 'dev-alpha' : 'dev-beta';
  const device = env.pki.devices.find((entry) => entry.id === id)!;
  return { cert: fs.readFileSync(device.certPath), key: fs.readFileSync(device.keyPath) };
}

function request(env: Env, path: string, options: FetchOptions = {}): Promise<FetchResult> {
  const device = options.device ?? 'alpha';
  const material = device === 'none' ? {} : certFor(env, device);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: '127.0.0.1',
        port: env.server.port,
        path,
        method: options.method ?? 'GET',
        rejectUnauthorized: false,
        ...material,
        headers: { ...options.headers, ...(options.cookie ? { cookie: options.cookie } : {}) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    req.on('error', reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

/** Extracts the cookie value for the proxy session cookie from a response. */
function sessionCookie(result: FetchResult): string | null {
  const cookies = result.headers['set-cookie'];
  if (cookies === undefined) return null;
  for (const cookie of Array.isArray(cookies) ? cookies : [cookies]) {
    const match = /^(zt_session=[^;]+)/.exec(cookie);
    if (match) return match[1]!;
  }
  return null;
}

async function login(env: Env, which: 'alpha' | 'beta', username: string, password: string): Promise<string> {
  const page = await request(env, '/login', { device: which });
  assert.equal(page.status, 200);
  const nonce = /name="nonce" value="([^"]+)"/.exec(page.body)?.[1];
  assert.ok(nonce, 'login page must include a nonce');
  const cookieHeader = page.headers['set-cookie'];
  const nonceCookie = (Array.isArray(cookieHeader) ? cookieHeader : [cookieHeader ?? '']).find((value) =>
    value.startsWith('zt_login_nonce='),
  );
  assert.ok(nonceCookie);
  const nonceValue = /^zt_login_nonce=([^;]+)/.exec(nonceCookie)![1];
  const result = await request(env, '/login', {
    device: which,
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: `zt_login_nonce=${nonceValue}`,
    },
    body: new URLSearchParams({ username, password, nonce: nonce! }).toString(),
  });
  assert.equal(result.status, 303, result.body);
  const session = sessionCookie(result);
  assert.ok(session, 'login must set a session cookie');
  return session;
}

let env: Env;

before(async () => {
  env = await buildEnv();
});

after(async () => {
  await env.close();
});

test('requests without a client certificate are rejected with 401', async () => {
  const result = await request(env, '/', { device: 'none' });
  assert.equal(result.status, 401);
  assert.match(result.body, /Device certificate required/);
});

test('login page shows the certificate-derived device identity', async () => {
  const result = await request(env, '/login');
  assert.equal(result.status, 200);
  assert.match(result.body, /dev-alpha/);
  assert.match(result.body, /user hint: admin/);
});

test('wrong password is rejected and audited', async () => {
  const page = await request(env, '/login');
  const nonce = /name="nonce" value="([^"]+)"/.exec(page.body)![1]!;
  const nonceCookie = (Array.isArray(page.headers['set-cookie']) ? page.headers['set-cookie'] : [page.headers['set-cookie'] ?? '']).find(
    (value) => value.startsWith('zt_login_nonce='),
  )!;
  const result = await request(env, '/login', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: `zt_login_nonce=${/^zt_login_nonce=([^;]+)/.exec(nonceCookie)![1]}`,
    },
    body: new URLSearchParams({ username: 'admin', password: 'wrong', nonce }).toString(),
  });
  assert.equal(result.status, 401);
  const denied = env.runtime.audit.recent(20, { action: 'auth.login' }).some((record) => record.decision === 'deny');
  assert.equal(denied, true);
});

test('login without the CSRF nonce cookie fails', async () => {
  const page = await request(env, '/login');
  const nonce = /name="nonce" value="([^"]+)"/.exec(page.body)![1]!;
  const result = await request(env, '/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'admin', password: 'admin-password', nonce }).toString(),
  });
  assert.equal(result.status, 401);
  assert.match(result.body, /expired/i);
});

test('session cookie from one device cannot be used from another device', async () => {
  const session = await login(env, 'alpha', 'admin', 'admin-password');
  const ok = await request(env, '/console', { cookie: session });
  assert.equal(ok.status, 200);
  // Same cookie, different certificate: sealed AAD mismatch -> login redirect.
  const stolen = await request(env, '/console', { device: 'beta', cookie: session });
  assert.equal(stolen.status, 303);
  assert.equal(stolen.headers.location, '/login');
  const audited = env.runtime.audit
    .recent(50, { action: 'session.token_invalid' })
    .some((record) => record.deviceId === 'dev-beta');
  assert.equal(audited, true);
});

test('proxy relays a request with verified identity headers', async () => {
  const session = await login(env, 'alpha', 'admin', 'admin-password');
  const result = await request(env, '/app/wiki/hello', { cookie: session });
  assert.equal(result.status, 200);
  const payload = JSON.parse(result.body) as Record<string, unknown>;
  assert.equal(payload.user, 'usr_admin');
  assert.equal(payload.device, 'dev-alpha');
  // The proxy's own cookie must not leak to the upstream.
  assert.equal(payload.cookie, null);
});

test('policy denial returns 403 and is audited', async () => {
  // emp is in the finance group with a laptop device; ops requires engineering.
  const session = await login(env, 'beta', 'emp', 'emp-password');
  const result = await request(env, '/app/ops/', { device: 'beta', cookie: session });
  assert.equal(result.status, 403);
  assert.match(result.body, /Access denied/);
  const denied = env.runtime.audit
    .recent(50, { action: 'app.access' })
    .some((record) => record.decision === 'deny' && record.appId === 'ops');
  assert.equal(denied, true);
});

test('payroll requires disk encryption: a healthy device passes', async () => {
  const session = await login(env, 'beta', 'emp', 'emp-password');
  const result = await request(env, '/app/payroll/', { device: 'beta', cookie: session });
  assert.equal(result.status, 200);
  const payload = JSON.parse(result.body) as Record<string, unknown>;
  assert.equal(payload.user, 'usr_emp');
});

test('a revoked session is refused even while the cookie is still sealed', async () => {
  const session = await login(env, 'alpha', 'admin', 'admin-password');
  const before = await request(env, '/console', { cookie: session });
  assert.equal(before.status, 200);
  // Target the session just created (listActive is oldest-first per device).
  const candidates = env.runtime.sessions.listActive().filter((entry) => entry.deviceId === 'dev-alpha');
  const record = candidates.at(-1);
  assert.ok(record);
  await new Promise((resolve) => setTimeout(resolve, 5));
  env.runtime.sessionManager.revokeSession(record, 'test revocation', new Date());
  const after = await request(env, '/console', { cookie: session });
  assert.equal(after.status, 303);
});

test('posture downgrade cuts a live proxy session (60s SLA)', async () => {
  const session = await login(env, 'alpha', 'admin', 'admin-password');
  const first = await request(env, '/app/ops/', { cookie: session });
  assert.equal(first.status, 200);

  const started = Date.now();
  // EDR goes offline on the device.
  env.posture.patch('dev-alpha', { edrOnline: false });
  await env.runtime.postureSync!.poll(['dev-alpha']);
  let lastStatus = 0;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const result = await request(env, '/app/ops/', { cookie: session });
    lastStatus = result.status;
    if (result.status !== 200) break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  const elapsed = Date.now() - started;
  assert.notEqual(lastStatus, 200, 'access must be cut after the downgrade');
  assert.ok(elapsed < 60_000, `revocation took ${elapsed}ms, SLA is 60000ms`);

  // Recover the device so later assertions see a healthy fleet.
  env.posture.patch('dev-alpha', { edrOnline: true });
  await env.runtime.postureSync!.poll(['dev-alpha']);
  await env.runtime.revalidator.runOnce('test-recover');
});

test('a grant is refused on the request path before the next background pass runs', async () => {
  const session = await login(env, 'beta', 'emp', 'emp-password');
  const first = await request(env, '/app/payroll/', { device: 'beta', cookie: session });
  assert.equal(first.status, 200);

  // Break posture but do NOT poll the sync layer or run a pass: the request
  // path itself must notice via checkGrantNow.
  env.runtime.posture.upsert({
    ...env.runtime.posture.get('dev-beta')!,
    diskEncrypted: false,
  });
  const denied = await request(env, '/app/payroll/', { device: 'beta', cookie: session });
  assert.equal(denied.status, 403);
  assert.match(denied.body, /diskEncrypted/);

  // Restore for subsequent tests.
  env.runtime.posture.upsert({ ...env.runtime.posture.get('dev-beta')!, diskEncrypted: true });
  await env.runtime.postureSync!.poll(['dev-beta']);
});

test('upstream redirects and cookies are rewritten into the app prefix', async () => {
  const session = await login(env, 'alpha', 'admin', 'admin-password');
  const redirect = await request(env, '/app/wiki/redirect-me', { cookie: session });
  assert.equal(redirect.status, 302);
  assert.equal(redirect.headers.location, '/app/wiki/landed');

  const cookie = await request(env, '/app/wiki/cookie', { cookie: session });
  assert.equal(cookie.status, 200);
  const setCookie = [cookie.headers['set-cookie']].flat().join(';');
  assert.match(setCookie, /Path=\/app\/wiki\//);
});

test('admin pages require the admin role', async () => {
  const empSession = await login(env, 'beta', 'emp', 'emp-password');
  const denied = await request(env, '/admin', { device: 'beta', cookie: empSession });
  assert.equal(denied.status, 403);

  const adminSession = await login(env, 'alpha', 'admin', 'admin-password');
  for (const page of ['/admin', '/admin/devices', '/admin/policy', '/admin/sessions', '/admin/audit']) {
    const result = await request(env, page, { cookie: adminSession });
    assert.equal(result.status, 200, `${page} returned ${result.status}`);
  }
  const adminHtml = await request(env, '/admin', { cookie: adminSession });
  assert.match(adminHtml.body, /Audit chain/);
  assert.match(adminHtml.body, /OK/);
});

test('audit chain stays valid through the whole run', async () => {
  const verification = env.runtime.audit.verify();
  assert.equal(verification.ok, true, verification.message);
  assert.ok(verification.records > 10);
});

test('rate limiting blocks repeated bad passwords', async () => {
  // Use a dedicated device/user pair so the shared counters stay clean.
  const page = await request(env, '/login', { device: 'beta' });
  const nonce = /name="nonce" value="([^"]+)"/.exec(page.body)![1]!;
  const nonceCookie = (Array.isArray(page.headers['set-cookie']) ? page.headers['set-cookie'] : [page.headers['set-cookie'] ?? '']).find(
    (value) => value.startsWith('zt_login_nonce='),
  )!;
  const cookie = `zt_login_nonce=${/^zt_login_nonce=([^;]+)/.exec(nonceCookie)![1]}`;
  for (let attempt = 0; attempt < 7; attempt += 1) {
    await request(env, '/login', {
      device: 'beta',
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams({ username: 'emp', password: 'nope', nonce }).toString(),
    });
  }
  const blocked = await request(env, '/login', {
    device: 'beta',
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ username: 'emp', password: 'emp-password', nonce }).toString(),
  });
  assert.equal(blocked.status, 401);
  assert.match(blocked.body, /Too many failed attempts/);
  void RUN;
});
