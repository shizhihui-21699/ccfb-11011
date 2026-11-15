/**
 * Mock upstream applications for the demo. Each app serves a small page that
 * echoes the identity headers the proxy injected, so you can see exactly what
 * reached the upstream and what was withheld.
 *
 *   node scripts/mock-apps.ts      (ports 9101–9103)
 */
import http from 'node:http';

interface MockApp {
  id: string;
  name: string;
  port: number;
  accent: string;
  body: string;
}

const APPS: MockApp[] = [
  {
    id: 'wiki',
    name: 'Internal Wiki',
    port: 9101,
    accent: '#4cc2ff',
    body: 'Company handbook, runbooks and architecture notes. This content lives on an internal host that is no longer reachable over VPN.',
  },
  {
    id: 'payroll',
    name: 'Payroll Admin',
    port: 9102,
    accent: '#3ddc97',
    body: 'Compensation records and payroll runs. Access is limited to the finance group and administrators, on encrypted devices.',
  },
  {
    id: 'ops-console',
    name: 'Operations Console',
    port: 9103,
    accent: '#ffcc5c',
    body: 'Production deployment controls. Requires disk encryption, EDR, firewall and a recent posture report.',
  },
];

function render(app: MockApp, headers: http.IncomingHttpHeaders, path: string): string {
  const identity: [string, string][] = [
    ['x-zt-user-id', String(headers['x-zt-user-id'] ?? '—')],
    ['x-zt-device-id', String(headers['x-zt-device-id'] ?? '—')],
    ['x-zt-session-id', String(headers['x-zt-session-id'] ?? '—')],
    ['x-zt-forwarded-path', String(headers['x-zt-forwarded-path'] ?? '—')],
    ['x-forwarded-for', String(headers['x-forwarded-for'] ?? '—')],
    ['cookie', String(headers['cookie'] ?? '(none — the proxy strips its own cookie)')],
  ];
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${app.name} (upstream)</title>
<style>
:root{color-scheme:dark}
body{margin:0;font-family:ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;background:#0b1017;color:#dbe6f3}
.wrap{max-width:760px;margin:0 auto;padding:36px 20px 64px}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;border:1px solid ${app.accent};color:${app.accent};font-size:.75rem;letter-spacing:.06em;text-transform:uppercase}
h1{font-size:1.5rem;margin:14px 0 6px}
p{color:#8395ab;line-height:1.6}
table{width:100%;border-collapse:collapse;margin-top:18px;font-size:.85rem;background:#121a25;border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #223043}
th{color:#8395ab;font-weight:500;width:38%}
td{font-family:ui-monospace,monospace;word-break:break-all}
a{color:${app.accent}}
</style></head>
<body><div class="wrap">
<span class="badge">upstream · ${app.id}</span>
<h1>${app.name}</h1>
<p>${app.body}</p>
<p>This page is served by the upstream on port ${app.port}. It never sees a VPN client, only a request the access proxy already authorized.</p>
<table>
<tr><th>Request path seen</th><td>${escapeHtml(path)}</td></tr>
${identity.map(([key, value]) => `<tr><th>${key}</th><td>${escapeHtml(value)}</td></tr>`).join('')}
</table>
<p style="margin-top:22px"><a href="/">Home</a> · <a href="/deep/link/page">A deeper path</a></p>
</div></body></html>`;
}

function escapeHtml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

const servers: http.Server[] = [];

export function startMockApps(): Promise<void> {
  return new Promise((resolve, reject) => {
    let pending = APPS.length;
    for (const app of APPS) {
      const server = http.createServer((req, res) => {
        if (req.url === '/healthz') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end('{"status":"ok"}');
          return;
        }
        if (req.url === '/redirect') {
          res.writeHead(302, { location: '/' });
          res.end();
          return;
        }
        if (req.url === '/set-cookie') {
          res.writeHead(200, { 'content-type': 'text/plain', 'set-cookie': 'upstream_session=abc123; Path=/' });
          res.end('cookie set');
          return;
        }
        const html = render(app, req.headers, req.url ?? '/');
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(html) });
        res.end(html);
      });
      servers.push(server);
      server.once('error', reject);
      server.listen(app.port, '127.0.0.1', () => {
        pending -= 1;
        if (pending === 0) resolve();
      });
    }
  });
}

export function stopMockApps(): Promise<void> {
  return Promise.all(
    servers.map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
        }),
    ),
  ).then(() => undefined);
}

if (import.meta.filename === process.argv[1]) {
  startMockApps()
    .then(() => {
      for (const app of APPS) console.log(`mock ${app.id.padEnd(12)} http://127.0.0.1:${app.port}`);
    })
    .catch((error: unknown) => {
      console.error(error);
      process.exit(1);
    });
}
