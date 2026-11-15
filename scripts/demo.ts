/**
 * Offline end-to-end demo. Starts the posture service, mock upstreams and the
 * access proxy in-process, then walks the scenarios an operator cares about:
 *
 *   1. compliant device signs in and reaches an application
 *   2. device/user mismatch is refused at sign-in
 *   3. a non-compliant device cannot sign in
 *   4. group authorization blocks an app even for a signed-in user
 *   5. a posture regression revokes a live session within the 60s SLA
 *   6. a revoked session stays revoked after posture recovers
 *   7. admin device revocation is immediate
 *   8. the audit chain is intact and contains the decisions
 *   9. certificate-less clients can read (only) the sign-in page
 *
 * All state is written to a temporary directory; the checked-in demo data is
 * never modified. Run with: npm run demo
 */
import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { copyFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROOT_DIR } from '../src/config.ts';
import { buildContext, startServer, type AppContext } from '../src/server.ts';
import { loadServiceConfig } from '../src/config.ts';
import { createPostureService } from '../src/postureService.ts';
import { createLogger, setLogLevel } from '../src/log.ts';
import { nowIso } from '../src/util.ts';
import { SEED_DEVICES } from './setup.ts';

const log = createLogger('demo');
setLogLevel('warn');

interface SimpleResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function call(
  port: number,
  method: string,
  path: string,
  options: { certId: string; cookies?: Record<string, string>; form?: Record<string, string> },
): Promise<SimpleResponse> {
  const certPath = join(ROOT_DIR, 'certs', 'devices', `${options.certId}.crt`);
  const keyPath = join(ROOT_DIR, 'certs', 'devices', `${options.certId}.key`);
  const headers: Record<string, string> = { host: `localhost:${port}` };
  if (options.cookies && Object.keys(options.cookies).length > 0) {
    headers.cookie = Object.entries(options.cookies)
      .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
      .join('; ');
  }
  let payload: string | undefined;
  if (options.form) {
    payload = new URLSearchParams(options.form).toString();
    headers['content-type'] = 'application/x-www-form-urlencoded';
    headers['content-length'] = String(Buffer.byteLength(payload));
  }

  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: '127.0.0.1',
        port,
        method,
        path,
        headers,
        ca: readFileSync(join(ROOT_DIR, 'certs', 'ca.crt')),
        cert: readFileSync(certPath),
        key: readFileSync(keyPath),
        servername: 'localhost',
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

function cookiesOf(response: SimpleResponse): Record<string, string> {
  const setCookie = response.headers['set-cookie'];
  const list = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  const jar: Record<string, string> = {};
  for (const cookie of list) {
    const pair = cookie.split(';')[0];
    const index = pair.indexOf('=');
    if (index > 0) jar[pair.slice(0, index).trim()] = decodeURIComponent(pair.slice(index + 1).trim());
  }
  return jar;
}

function extractCsrf(html: string): string | undefined {
  return /name="csrf" value="([^"]+)"/.exec(html)?.[1];
}

const credentials = JSON.parse(readFileSync(join(ROOT_DIR, 'data', 'demo-credentials.json'), 'utf8')) as Record<string, string>;
const agentTokens = JSON.parse(readFileSync(join(ROOT_DIR, 'data', 'agent-tokens.json'), 'utf8')) as {
  tokens: Record<string, string>;
};

async function signIn(port: number, userId: string, certId: string): Promise<Record<string, string>> {
  const loginPage = await call(port, 'GET', '/_zta/login', { certId });
  const csrf = extractCsrf(loginPage.body);
  if (!csrf) throw new Error(`no csrf token on login page (status ${loginPage.status})`);
  const post = await call(port, 'POST', '/_zta/login', {
    certId,
    cookies: cookiesOf(loginPage),
    form: { username: userId, password: credentials[userId], csrf, next: '/' },
  });
  const jar = cookiesOf(post);
  if (!jar['__Host-zta_session']) {
    const banner = /<div class="banner[^"]*">([^<]+)</.exec(post.body)?.[1] ?? post.body.slice(0, 200);
    throw new Error(`sign-in failed for ${userId}/${certId} (status ${post.status}): ${banner}`);
  }
  return jar;
}

function reportPosture(port: number, deviceId: string, overrides: Record<string, unknown> = {}): Promise<number> {
  const seed = SEED_DEVICES.find((device) => device.id === deviceId);
  if (!seed) throw new Error(`unknown seed device ${deviceId}`);
  const body = JSON.stringify({
    deviceId,
    platform: seed.platform,
    osVersion: seed.posture.osVersion,
    diskEncrypted: seed.posture.diskEncrypted,
    edrInstalled: seed.posture.edrInstalled,
    edrRunning: seed.posture.edrRunning,
    edrLastHeartbeatAt: nowIso(),
    reportedAt: nowIso(),
    ...overrides,
  });
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: '/v1/report',
        headers: {
          'content-type': 'application/json',
          'content-length': String(Buffer.byteLength(body)),
          'x-agent-token': agentTokens.tokens[deviceId],
        },
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode ?? 0));
      },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function mockUpstream(port: number): ReturnType<typeof createHttpServer> {
  return createHttpServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        app: `mock@${port}`,
        path: req.url,
        asserted: {
          user: req.headers['x-zta-user'],
          device: req.headers['x-zta-device'],
          posture: req.headers['x-zta-posture'],
          groups: req.headers['x-zta-groups'],
        },
      }),
    );
  });
}

const results: { name: string; ok: boolean; detail: string }[] = [];
function check(name: string, ok: boolean, detail: string): void {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}\n      ${detail}`);
}

async function main(): Promise<void> {
  const workDir = mkdtempSync(join(tmpdir(), 'zta-demo-'));
  copyFileSync(join(ROOT_DIR, 'data', 'devices.json'), join(workDir, 'devices.json'));
  const postureService = createPostureService({ port: 0, dataFile: join(workDir, 'posture.json') });
  const posturePort = await postureService.listen('127.0.0.1', 0);

  process.env.ZTA_POSTURE_URL = `http://127.0.0.1:${posturePort}`;
  process.env.ZTA_PORT = '0';
  process.env.ZTA_DEVICES_FILE = join(workDir, 'devices.json');
  process.env.ZTA_AUDIT_FILE = join(workDir, 'audit.jsonl');
  const ctx: AppContext = buildContext(loadServiceConfig());
  const proxy = await startServer(ctx);
  const port = proxy.port;
  ctx.enforcer.start();

  for (const device of SEED_DEVICES) {
    const status = await reportPosture(posturePort, device.id, {
      edrLastHeartbeatAt: new Date().toISOString(),
      reportedAt: new Date().toISOString(),
    });
    if (status !== 202) throw new Error(`posture seed for ${device.id} failed: ${status}`);
  }

  const mockPorts = [8460, 8461, 8462];
  const mocks = mockPorts.map((mockPort) => mockUpstream(mockPort).listen(mockPort, '127.0.0.1'));

  try {
    // 1. Compliant device reaches an app
    const aliceJar = await signIn(port, 'alice', 'dev-alice-macbook');
    const wiki = await call(port, 'GET', '/wiki/index.html', { certId: 'dev-alice-macbook', cookies: aliceJar });
    check(
      'compliant device reaches wiki',
      wiki.status === 200 && wiki.body.includes('mock@8460') && wiki.body.includes('"user":"alice"'),
      `status ${wiki.status}, upstream mock@8460=${wiki.body.includes('mock@8460')}`,
    );

    // 2. Valid certificate, but not the device assigned to the user
    const mismatchPage = await call(port, 'GET', '/_zta/login', { certId: 'dev-carol-linux' });
    const mismatch = await call(port, 'POST', '/_zta/login', {
      certId: 'dev-carol-linux',
      cookies: cookiesOf(mismatchPage),
      form: {
        username: 'alice',
        password: credentials.alice,
        csrf: extractCsrf(mismatchPage.body) ?? '',
        next: '/',
      },
    });
    check(
      'device/user mismatch refused at sign-in',
      mismatch.status === 403 && mismatch.body.includes('not assigned to alice'),
      `status ${mismatch.status}`,
    );

    // 3. Carol's device fails the posture baseline
    const carolPage = await call(port, 'GET', '/_zta/login', { certId: 'dev-carol-linux' });
    const carolPost = await call(port, 'POST', '/_zta/login', {
      certId: 'dev-carol-linux',
      cookies: cookiesOf(carolPage),
      form: { username: 'carol', password: credentials.carol, csrf: extractCsrf(carolPage.body) ?? '', next: '/' },
    });
    check(
      'non-compliant device blocked at sign-in',
      carolPost.status === 403 && /posture check failed/i.test(carolPost.body),
      `status ${carolPost.status}`,
    );

    // 4. Group authorization: engineering cannot reach finance
    const finance = await call(port, 'GET', '/finance/report', { certId: 'dev-alice-macbook', cookies: aliceJar });
    check(
      'group authorization denies finance to engineering',
      finance.status === 403 && finance.body.includes('not authorized'),
      `status ${finance.status}`,
    );

    // 5. Posture regression revokes the live session within the SLA
    await reportPosture(posturePort, 'dev-alice-macbook', { edrRunning: false });
    const started = Date.now();
    let revokedAfterSeconds = -1;
    for (let i = 0; i < 80; i += 1) {
      const probe = await call(port, 'GET', '/wiki/index.html', { certId: 'dev-alice-macbook', cookies: aliceJar });
      if (probe.status === 302) {
        revokedAfterSeconds = Math.round((Date.now() - started) / 1000);
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    check(
      'posture regression revokes live session within SLA',
      revokedAfterSeconds >= 0 && revokedAfterSeconds <= 60,
      `revoked after ~${revokedAfterSeconds}s (SLA ${ctx.policy.settings.revocationSlaSeconds}s, recheck ${ctx.policy.settings.postureRecheckSeconds}s)`,
    );

    // 6. Recovery does not resurrect the old session
    await reportPosture(posturePort, 'dev-alice-macbook');
    await new Promise((resolve) => setTimeout(resolve, 2_500));
    const afterRestore = await call(port, 'GET', '/wiki/index.html', { certId: 'dev-alice-macbook', cookies: aliceJar });
    check('revoked session stays revoked after posture recovers', afterRestore.status === 302, `status ${afterRestore.status}`);

    // 7. Admin revocation of a device cuts its session immediately
    const bobJar = await signIn(port, 'bob', 'dev-bob-thinkpad');
    const bobBefore = await call(port, 'GET', '/finance/report', { certId: 'dev-bob-thinkpad', cookies: bobJar });
    const adminJar = await signIn(port, 'admin', 'dev-admin-mac');
    const adminPage = await call(port, 'GET', '/_zta/', { certId: 'dev-admin-mac', cookies: adminJar });
    const adminCsrf = extractCsrf(adminPage.body) ?? '';
    const revoke = await call(port, 'POST', '/_zta/admin/devices/dev-bob-thinkpad/revoke', {
      certId: 'dev-admin-mac',
      cookies: adminJar,
      form: { csrf: adminCsrf },
    });
    const bobAfter = await call(port, 'GET', '/finance/report', { certId: 'dev-bob-thinkpad', cookies: bobJar });
    check(
      'admin device revocation cuts the live session immediately',
      bobBefore.status === 200 && revoke.status === 302 && bobAfter.status === 302,
      `before=${bobBefore.status} revoke=${revoke.status} after=${bobAfter.status}`,
    );

    // 8. Audit chain
    const chain = ctx.audit.verifyChain();
    const events = new Set(ctx.audit.recent(600).map((entry) => entry.event));
    const required = ['access.allow', 'access.deny', 'session.revoked', 'auth.login.success'];
    check(
      'audit chain intact and records every decision type',
      chain.valid && required.every((event) => events.has(event as never)),
      `valid=${chain.valid}, entries=${chain.entries}, present=${required.filter((event) => events.has(event as never)).join(',')}`,
    );

    // 9. A session cookie is bound to the certificate that created it: replaying
    //    it from another machine (a different, still-valid certificate) fails
    //    and kills the session.
    const aliceAgain = await signIn(port, 'alice', 'dev-alice-macbook');
    const replay = await call(port, 'GET', '/_zta/', { certId: 'dev-admin-mac', cookies: aliceAgain });
    check(
      'session cookie cannot be replayed with a different certificate',
      replay.status === 302,
      `status ${replay.status}`,
    );
    const afterReplay = await call(port, 'GET', '/_zta/', { certId: 'dev-alice-macbook', cookies: aliceAgain });
    check(
      'replayed session is revoked for its real owner too',
      afterReplay.status === 302,
      `status ${afterReplay.status}`,
    );

    // 10. Certificate-less client gets only the sign-in page
    const noCert = await new Promise<number>((resolve, reject) => {
      const req = httpsRequest(
        {
          host: '127.0.0.1',
          port,
          path: '/_zta/login',
          ca: readFileSync(join(ROOT_DIR, 'certs', 'ca.crt')),
          servername: 'localhost',
        },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode ?? 0));
        },
      );
      req.on('error', reject);
      req.end();
    });
    const noCertConsole = await new Promise<number>((resolve, reject) => {
      const req = httpsRequest(
        {
          host: '127.0.0.1',
          port,
          path: '/_zta/',
          ca: readFileSync(join(ROOT_DIR, 'certs', 'ca.crt')),
          servername: 'localhost',
        },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode ?? 0));
        },
      );
      req.on('error', reject);
      req.end();
    });
    check(
      'certificate-less client sees sign-in page but not the console',
      noCert === 200 && noCertConsole === 302,
      `login=${noCert} console=${noCertConsole}`,
    );
  } finally {
    for (const mock of mocks) mock.close();
    ctx.enforcer.stop();
    await postureService.close();
    await proxy.close();
    rmSync(workDir, { recursive: true, force: true });
  }

  const failed = results.filter((result) => !result.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length > 0) process.exitCode = 1;
  log.debug('demo finished');
}

await main();
