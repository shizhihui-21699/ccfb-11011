import express from 'express';
import { AuditLog } from './audit';
import { SessionStore } from './sessions';
import { loadPolicies } from './policy';
import { fetchDevices } from './posture';

export const ADMIN_PORT = 8200;

const PAGE = `<!doctype html>
<html><head><title>ZTNA Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{font-family:system-ui;margin:0;padding:1.5rem 2rem;background:#f6f7f9;color:#222}
  h1{font-size:1.3rem} h2{font-size:1rem;margin-top:1.5rem;color:#444}
  table{border-collapse:collapse;width:100%;background:#fff;font-size:.85rem}
  th,td{border:1px solid #e2e4e8;padding:.4rem .6rem;text-align:left;vertical-align:top}
  th{background:#eef0f3}
  .ok{color:#0a7a2f;font-weight:600}.bad{color:#b00020;font-weight:600}
  code{background:#eef0f3;padding:.1rem .3rem;border-radius:3px}
  #updated{color:#888;font-size:.8rem}
</style></head><body>
<h1>Zero-Trust Admin</h1>
<div id="updated"></div>

<h2>Devices &amp; Posture</h2>
<table id="devices"><thead><tr>
<th>Device</th><th>OS</th><th>Disk encrypted</th><th>EDR online</th><th>Last report</th>
</tr></thead><tbody></tbody></table>

<h2>Active Sessions</h2>
<table id="sessions"><thead><tr>
<th>User</th><th>Device</th><th>Apps in use</th><th>Created</th>
</tr></thead><tbody></tbody></table>

<h2>Application Policies</h2>
<table id="policies"><thead><tr>
<th>App</th><th>Upstream</th><th>Allowed users</th><th>Requirements</th>
</tr></thead><tbody></tbody></table>

<h2>Audit Log (latest 100)</h2>
<table id="audit"><thead><tr>
<th>Time</th><th>Event</th><th>Outcome</th><th>User</th><th>Device</th><th>App</th><th>Reason</th>
</tr></thead><tbody></tbody></table>

<script>
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const yn = b => b ? '<span class="ok">yes</span>' : '<span class="bad">no</span>';
const ago = ts => { const s = Math.round((Date.now()-ts)/1000); return s < 60 ? s+'s ago' : Math.round(s/60)+'m ago'; };

async function refresh() {
  const [devices, sessions, policies, audit] = await Promise.all(
    ['/api/devices','/api/sessions','/api/policies','/api/audit'].map(u => fetch(u).then(r => r.json())));

  document.querySelector('#devices tbody').innerHTML = devices.map(d => \`<tr>
    <td><code>\${esc(d.deviceId)}</code></td><td>\${esc(d.osVersion)}</td>
    <td>\${yn(d.diskEncrypted)}</td><td>\${yn(d.edrOnline)}</td>
    <td>\${ago(d.reportedAt)}</td></tr>\`).join('') || '<tr><td colspan="5">no posture reports yet</td></tr>';

  document.querySelector('#sessions tbody').innerHTML = sessions.map(s => \`<tr>
    <td>\${esc(s.user)}</td><td><code>\${esc(s.deviceId)}</code></td>
    <td>\${esc(s.grantedApps.join(', ') || '—')}</td>
    <td>\${new Date(s.createdAt).toLocaleTimeString()}</td></tr>\`).join('') || '<tr><td colspan="4">no active sessions</td></tr>';

  document.querySelector('#policies tbody').innerHTML = Object.entries(policies.apps).map(([name, p]) => \`<tr>
    <td><b>\${esc(name)}</b></td><td><code>\${esc(p.upstream)}</code></td>
    <td>\${esc(p.allowUsers.join(', '))}</td>
    <td><code>\${esc(JSON.stringify(p.require))}</code></td></tr>\`).join('');

  document.querySelector('#audit tbody').innerHTML = audit.map(e => \`<tr>
    <td>\${new Date(e.ts).toLocaleTimeString()}</td><td>\${esc(e.kind)}</td>
    <td class="\${e.outcome === 'allow' || e.outcome === 'info' ? 'ok' : 'bad'}">\${esc(e.outcome)}</td>
    <td>\${esc(e.user || '')}</td><td><code>\${esc(e.deviceId || '')}</code></td>
    <td>\${esc(e.app || '')}</td><td>\${esc(e.reason || '')}</td></tr>\`).join('');

  document.getElementById('updated').textContent = 'updated ' + new Date().toLocaleTimeString();
}
refresh();
setInterval(refresh, 3000);
</script>
</body></html>`;

/** Admin console — localhost only, shows devices, sessions, policies, audit. */
export function startAdmin(audit: AuditLog, sessions: SessionStore): void {
  const app = express();

  app.get('/', (_req, res) => res.send(PAGE));

  app.get('/api/devices', async (_req, res) => res.json(await fetchDevices()));

  app.get('/api/sessions', (_req, res) =>
    res.json(
      sessions.list().map((s) => ({
        user: s.user,
        deviceId: s.deviceId,
        createdAt: s.createdAt,
        grantedApps: [...s.grantedApps],
      })),
    ),
  );

  app.get('/api/policies', (_req, res) => res.json(loadPolicies()));

  app.get('/api/audit', (_req, res) => res.json(audit.recent(100)));

  app.listen(ADMIN_PORT, '127.0.0.1', () => {
    console.log(`[admin] console on http://127.0.0.1:${ADMIN_PORT}`);
  });
}
