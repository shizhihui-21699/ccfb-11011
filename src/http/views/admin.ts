/**
 * Admin console pages: fleet overview, device inventory with posture, policy
 * rules as evaluated, session/grant inventory, and the audit log with chain
 * verification.
 *
 * All pages require an authenticated session whose user has the `admin` role;
 * the dispatcher in `server.ts` enforces that before rendering.
 */
import type { AppDefinition, Config } from '../../config.ts';
import type { PolicyDocument } from '../../policy/engine.ts';
import type { RevalidationReport } from '../../core/revalidator.ts';
import type { SyncStatus } from '../../services/posture-sync.ts';
import type {
  AuditRecord,
  DeviceRecord,
  GrantRecord,
  PostureSnapshotRecord,
  SessionRecord,
  UserRecord,
} from '../../store/types.ts';
import type { ChainVerification } from '../../store/audit.ts';
import { escapeHtml } from '../respond.ts';
import { decisionPill, layout, relativeTime } from './layout.ts';
import { formatFingerprint } from '../../pki/trust.ts';

const STYLE = `
.stat-grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(min(100%, 180px), 1fr)); margin-bottom: 22px; }
.stat { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 16px; }
.stat .n { font-size: 1.7rem; font-weight: 650; line-height: 1.1; }
.stat .k { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 6px; }
.stat .sub { color: var(--muted); font-size: 0.8rem; margin-top: 8px; }
.device-flag { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.device-flag.ok { background: var(--allow); }
.device-flag.bad { background: var(--deny); }
.device-flag.stale { background: var(--warn); }
.actions-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.rules { display: grid; gap: 12px; }
.rule { background: var(--panel-2); border: 1px solid var(--line); border-left: 3px solid var(--line); border-radius: 10px; padding: 14px; }
.rule.allow { border-left-color: var(--allow); }
.rule.deny { border-left-color: var(--deny); }
.rule .head { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; }
.rule .id { font-family: ui-monospace, monospace; font-weight: 600; }
.rule .desc { color: var(--muted); font-size: 0.86rem; margin-top: 6px; }
.rule .meta { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.rule .meta .pill { font-weight: 500; }
.audit-detail { max-width: 340px; }
.stat-grid.tight { margin-bottom: 16px; }
.sla { display: flex; flex-wrap: wrap; gap: 16px; align-items: center; font-size: 0.85rem; }
.sla .num { font-variant-numeric: tabular-nums; font-weight: 650; }
`;

export interface AdminContext {
  nonce: string;
  runtime: {
    config: Config;
    users: UserRecord[];
    devices: DeviceRecord[];
    sessions: SessionRecord[];
    grants: GrantRecord[];
    posture: PostureSnapshotRecord[];
    auditRecords: AuditRecord[];
    policy: PolicyDocument;
    policyUpdatedAt: Date;
    policyLoadError: string | null;
    chain: ChainVerification;
    revalidation: RevalidationReport | null;
    postureStatus: SyncStatus | null;
    revalidationIntervalMs: number;
    postureMaxAgeSeconds: number;
  };
}

/** Human-readable rendering of a version floor. */
function describeFloor(floor: import('../../util/version.ts').VersionFloor | undefined): string {
  if (floor === undefined) return 'none configured';
  if (typeof floor === 'string') return floor;
  return Object.entries(floor)
    .map(([family, version]) => `${family} ${version}`)
    .join(', ');
}

export function adminLayout(ctx: AdminContext, title: string, body: string, head = ''): string {
  return layout({
    title,
    nonce: ctx.nonce,
    body,
    head: STYLE + head,
    operator: true,
    badge: 'operator',
    revalidateSeconds: Math.round(ctx.runtime.revalidationIntervalMs / 1000),
  });
}

/** Landing page: fleet health at a glance. */
export function adminOverviewPage(ctx: AdminContext): string {
  const { config, devices, sessions, grants, posture, chain, revalidation, postureStatus } = ctx.runtime;
  const postureByDevice = new Map(posture.map((snapshot) => [snapshot.deviceId, snapshot]));
  const now = Date.now();
  let healthy = 0;
  let degraded = 0;
  let stale = 0;
  for (const device of devices) {
    if (device.status !== 'enrolled') continue;
    const snapshot = postureByDevice.get(device.id);
    if (snapshot === undefined) {
      degraded += 1;
      continue;
    }
    const age = Math.floor((now - new Date(snapshot.collectedAt).getTime()) / 1000);
    if (age > config.thresholds.postureMaxAgeSeconds) stale += 1;
    else if (!snapshot.diskEncrypted || !snapshot.edrOnline) degraded += 1;
    else healthy += 1;
  }

  const lastPass = revalidation;
  const slaOk = lastPass === null || lastPass.durationMs < config.thresholds.revokeWithinMs;
  const enrolled = devices.filter((device) => device.status === 'enrolled').length;

  const stats = `
<div class="stat-grid">
  <div class="stat"><div class="n">${enrolled}</div><div class="k">Enrolled devices</div><div class="sub">${devices.length - enrolled} revoked</div></div>
  <div class="stat"><div class="n" style="color:var(--allow)">${healthy}</div><div class="k">Healthy</div><div class="sub">posture ok</div></div>
  <div class="stat"><div class="n" style="color:var(--warn)">${degraded}</div><div class="k">Degraded</div><div class="sub">EDR off / no encryption</div></div>
  <div class="stat"><div class="n" style="color:var(--deny)">${stale}</div><div class="k">Stale posture</div><div class="sub">&gt; ${config.thresholds.postureMaxAgeSeconds}s old</div></div>
  <div class="stat"><div class="n">${sessions.length}</div><div class="k">Live sessions</div><div class="sub">${grants.length} active grants</div></div>
  <div class="stat"><div class="n" style="color:${chain.ok ? 'var(--allow)' : 'var(--deny)'}">${chain.ok ? 'OK' : 'BROKEN'}</div><div class="k">Audit chain</div><div class="sub">${chain.records} records · ${chain.anchors} anchors</div></div>
</div>`;

  const pass = lastPass
    ? `<div class="sla">
    <span>Last pass: <span class="num">${relativeTime(lastPass.finishedAt)}</span></span>
    <span>Considered: <span class="num">${lastPass.considered}</span></span>
    <span>Revoked grants: <span class="num">${lastPass.revokedGrants}</span></span>
    <span>Revoked sessions: <span class="num">${lastPass.revokedSessions}</span></span>
    <span>Pass duration: <span class="num">${lastPass.durationMs}ms</span></span>
    <span class="pill ${slaOk ? 'allow' : 'deny'}">SLA ${config.thresholds.revokeWithinMs / 1000}s ${slaOk ? 'within' : 'at risk'}</span>
  </div>`
    : '<span class="muted">No revalidation pass recorded yet.</span>';

  const postureService = postureStatus
    ? `<div class="sla">
    <span>Last poll: <span class="num">${postureStatus.lastPollAt ? relativeTime(postureStatus.lastPollAt) : 'never'}</span></span>
    <span>Stream: ${postureStatus.streamConnected ? '<span class="pill allow">connected</span>' : '<span class="pill warn">polling only</span>'}</span>
    <span>Polls: <span class="num">${postureStatus.pollCount}</span></span>
    ${postureStatus.lastPollError ? `<span class="pill deny">${escapeHtml(postureStatus.lastPollError)}</span>` : ''}
  </div>`
    : '<span class="muted">Posture sync disabled.</span>';

  const body = `
<h1>Fleet overview</h1>
<p class="lede">Continuous authorization status. Every live grant is re-evaluated every ${Math.round(ctx.runtime.revalidationIntervalMs / 1000)}s, and immediately when a device's posture changes.</p>
${stats}
<section class="panel" style="margin-bottom:18px"><h2>Revalidation</h2>${pass}</section>
<section class="panel" style="margin-bottom:18px"><h2>Posture service</h2>${postureService}</section>
<section class="panel">
  <h2>Recent decisions</h2>
  <div class="tablewrap">
  <table>
    <thead><tr><th>Time</th><th>Decision</th><th>Action</th><th>Actor</th><th>Reason</th></tr></thead>
    <tbody>
    ${ctx.runtime.auditRecords
      .slice(0, 12)
      .map(
        (record) => `<tr>
        <td class="muted small">${relativeTime(record.ts)}</td>
        <td>${decisionPill(record.decision)}</td>
        <td class="mono small">${escapeHtml(record.action)}</td>
        <td class="mono small">${escapeHtml(record.actorId)}</td>
        <td class="small">${escapeHtml(record.reason)}</td>
      </tr>`,
      )
      .join('')}
    </tbody>
  </table>
  </div>
  <p style="margin-top:14px"><a class="btn" href="/admin/audit">Open audit log</a></p>
</section>`;
  return adminLayout(ctx, 'Admin', body);
}

/** Device inventory with posture details and per-device session counts. */
export function adminDevicesPage(ctx: AdminContext): string {
  const { config, devices, posture } = ctx.runtime;
  const postureByDevice = new Map(posture.map((snapshot) => [snapshot.deviceId, snapshot]));
  const sessionsByDevice = new Map<string, number>();
  for (const session of ctx.runtime.sessions) {
    sessionsByDevice.set(session.deviceId, (sessionsByDevice.get(session.deviceId) ?? 0) + 1);
  }
  const now = Date.now();

  const rows = devices
    .map((device) => {
      const snapshot = postureByDevice.get(device.id);
      let flag = 'bad';
      let postureCells = '<td colspan="5" class="muted small">never reported</td>';
      if (snapshot) {
        const age = Math.floor((now - new Date(snapshot.collectedAt).getTime()) / 1000);
        const stale = age > config.thresholds.postureMaxAgeSeconds;
        const healthy = !stale && snapshot.diskEncrypted && snapshot.edrOnline;
        flag = healthy ? 'ok' : stale ? 'stale' : 'bad';
        postureCells = `
          <td>${escapeHtml(snapshot.osName)} <span class="mono">${escapeHtml(snapshot.osVersion)}</span></td>
          <td>${snapshot.diskEncrypted ? '<span class="pill allow">on</span>' : '<span class="pill deny">off</span>'}</td>
          <td>${snapshot.edrOnline ? '<span class="pill allow">online</span>' : '<span class="pill deny">offline</span>'}<div class="muted small">${escapeHtml(snapshot.edrProduct)}</div></td>
          <td class="muted small">${escapeHtml(snapshot.patchLevel)}</td>
          <td class="muted small">${stale ? `<span class="pill warn">stale</span> ` : ''}${relativeTime(snapshot.collectedAt, new Date(now))}</td>`;
      }
      return `<tr>
        <td><span class="device-flag ${flag}"></span><strong>${escapeHtml(device.displayName)}</strong>
          <div class="mono small muted">${escapeHtml(device.id)}</div>
          ${device.status === 'revoked' ? `<span class="pill deny">revoked</span> <span class="muted small">${escapeHtml(device.revokedReason ?? '')}</span>` : ''}
        </td>
        <td class="small">${escapeHtml(device.group ?? '—')}<div class="muted small">owner ${escapeHtml(device.ownerUserId ?? 'unassigned')}</div></td>
        <td class="mono small">${escapeHtml(formatFingerprint(device.certFingerprint256).slice(0, 23))}…<div class="muted">expires ${escapeHtml(device.certExpiresAt.slice(0, 10))}</div></td>
        ${postureCells}
        <td class="small">${sessionsByDevice.get(device.id) ?? 0}</td>
      </tr>`;
    })
    .join('');

  const body = `
<h1>Devices</h1>
<p class="lede">Devices are identified solely by the certificate presented at the TLS layer. Posture comes from the local posture service.</p>
<section class="panel">
  <div class="tablewrap">
  <table>
    <thead><tr><th>Device</th><th>Group / owner</th><th>Certificate</th><th>OS</th><th>Disk</th><th>EDR</th><th>Patch</th><th>Posture age</th><th>Sessions</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  </div>
</section>
<p class="muted small" style="margin-top:14px">Fingerprints are SHA-256 of the DER certificate. Posture staleness threshold is ${config.thresholds.postureMaxAgeSeconds}s.</p>`;
  return adminLayout(ctx, 'Devices', body);
}

/** Policy as the engine sees it, per app. */
export function adminPolicyPage(ctx: AdminContext, apps: AppDefinition[]): string {
  const { policy, policyUpdatedAt, policyLoadError, config } = ctx.runtime;
  const appMap = new Map(apps.map((app) => [app.id, app]));
  const rules = policy.rules
    .map((rule) => {
      const appNames = rule.apps.map((appId) =>
        appId === '*' ? '<span class="pill neutral">all apps</span>' : `<span class="pill neutral">${escapeHtml(appMap.get(appId)?.name ?? appId)}</span>`,
      );
      const conditions: string[] = [];
      if (rule.groups) conditions.push(`groups: ${rule.groups.join(', ')}`);
      if (rule.roles) conditions.push(`roles: ${rule.roles.join(', ')}`);
      if (rule.users) conditions.push(`users: ${rule.users.join(', ')}`);
      if (rule.deviceGroups) conditions.push(`device groups: ${rule.deviceGroups.join(', ')}`);
      if (rule.deviceIds) conditions.push(`devices: ${rule.deviceIds.join(', ')}`);
      const reqs: string[] = [];
      if (rule.requireDiskEncrypted) reqs.push('disk encryption');
      if (rule.requireEdrOnline) reqs.push('EDR online');
      if (rule.requireFirewall) reqs.push('firewall');
      if (rule.osFamilies) reqs.push(`OS: ${rule.osFamilies.join('/')}`);
      reqs.push(`min OS ${describeFloor(rule.minOsVersion)}`);
      if (rule.maxPostureAgeSeconds) reqs.push(`posture ≤ ${rule.maxPostureAgeSeconds}s`);
      if (rule.allowMissingPosture) reqs.push('missing posture allowed');
      return `
<div class="rule ${rule.effect}">
  <div class="head"><span class="id">${escapeHtml(rule.id)}</span>${rule.effect === 'allow' ? '<span class="pill allow">allow</span>' : '<span class="pill deny">deny</span>'}</div>
  ${rule.description ? `<div class="desc">${escapeHtml(rule.description)}</div>` : ''}
  <div class="meta">${appNames.join(' ')}</div>
  ${conditions.length > 0 ? `<div class="desc">${escapeHtml(conditions.join(' · '))}</div>` : ''}
  <div class="meta">${reqs.map((req) => `<span class="pill neutral">${escapeHtml(req)}</span>`).join(' ')}</div>
</div>`;
    })
    .join('');

  const body = `
<h1>Policy</h1>
<p class="lede">Rules are evaluated top to bottom; the first applicable rule wins. No match means deny. File-loaded from <span class="mono">config/policy.json</span>, last loaded ${relativeTime(policyUpdatedAt)}.</p>
${policyLoadError ? `<div class="alert error">Policy reload failed: ${escapeHtml(policyLoadError)}. The previous policy remains in force.</div>` : ''}
<div class="stat-grid tight">
  <div class="stat"><div class="n">${policy.rules.length}</div><div class="k">Rules</div></div>
  <div class="stat"><div class="n">${policy.rules.filter((rule) => rule.effect === 'allow').length}</div><div class="k">Allow rules</div></div>
  <div class="stat"><div class="n">${policy.rules.filter((rule) => rule.effect === 'deny').length}</div><div class="k">Deny rules</div></div>
  <div class="stat"><div class="n" style="font-size:1.1rem">${escapeHtml(policy.defaultDenyReason ?? 'default deny')}</div><div class="k">Default</div></div>
</div>
<section class="panel"><div class="rules">${rules}</div></section>
<p class="muted small" style="margin-top:14px">Global device baseline: disk encryption, EDR online, posture ≤ ${config.thresholds.postureMaxAgeSeconds}s and the per-OS minimums ${escapeHtml(describeFloor(config.thresholds.minOsVersion))}. Policy rules can tighten but cannot relax the baseline.</p>`;
  return adminLayout(ctx, 'Policy', body);
}

/** Sessions and grants inventory. */
export function adminSessionsPage(ctx: AdminContext): string {
  const users = new Map(ctx.runtime.users.map((user) => [user.id, user]));
  const sessionRows = ctx.runtime.sessions
    .map((session) => {
      const user = users.get(session.userId);
      const grants = ctx.runtime.grants.filter((grant) => grant.sessionId === session.id);
      return `<tr>
        <td class="mono small">${escapeHtml(session.id)}</td>
        <td>${escapeHtml(user?.displayName ?? session.userId)}<div class="muted small mono">${escapeHtml(session.deviceId)}</div></td>
        <td class="small">${relativeTime(session.createdAt)}<div class="muted small">expires ${escapeHtml(session.expiresAt.slice(11, 19))}Z</div></td>
        <td>${grants.length > 0 ? grants.map((grant) => `<span class="pill ${grant.state === 'active' ? 'allow' : 'deny'}">${escapeHtml(grant.appId)}</span>`).join(' ') : '<span class="muted small">—</span>'}</td>
        <td class="small mono">${escapeHtml(session.ip)}</td>
      </tr>`;
    })
    .join('');

  const grantRows = ctx.runtime.grants
    .map((grant) => `<tr>
      <td><span class="pill ${grant.lastDecision === 'allow' ? 'allow' : 'deny'}">${escapeHtml(grant.appId)}</span></td>
      <td class="mono small">${escapeHtml(grant.userId)}<div class="muted">${escapeHtml(grant.deviceId)}</div></td>
      <td class="small">${grant.lastDecision === 'allow' ? 'allowed' : 'denied'}<div class="muted small">${relativeTime(grant.lastEvaluatedAt)}</div></td>
      <td class="small">${escapeHtml(grant.lastReason.slice(0, 120))}</td>
    </tr>`)
    .join('');

  const body = `
<h1>Sessions &amp; grants</h1>
<p class="lede">A session comes from login; a grant authorizes one application and is independently revocable.</p>
<section class="panel" style="margin-bottom:18px">
  <h2>Active sessions (${ctx.runtime.sessions.length})</h2>
  <div class="tablewrap"><table><thead><tr><th>Session</th><th>User / device</th><th>Created</th><th>Grants</th><th>IP</th></tr></thead><tbody>${sessionRows || '<tr><td colspan="5" class="muted">none</td></tr>'}</tbody></table></div>
</section>
<section class="panel">
  <h2>Active grants (${ctx.runtime.grants.length})</h2>
  <div class="tablewrap"><table><thead><tr><th>App</th><th>Identity</th><th>Last evaluation</th><th>Reason</th></tr></thead><tbody>${grantRows || '<tr><td colspan="4" class="muted">none</td></tr>'}</tbody></table></div>
</section>`;
  return adminLayout(ctx, 'Sessions', body);
}

/** Audit log with verification summary and export link. */
export function adminAuditPage(
  ctx: AdminContext,
  options: { action: string | null; deviceId: string | null; decision: string | null },
): string {
  const chain = ctx.runtime.chain;
  const rows = ctx.runtime.auditRecords
    .map((record) => `<tr>
      <td class="muted small mono">#${record.id}</td>
      <td class="muted small">${escapeHtml(record.ts.slice(0, 19).replace('T', ' '))}Z</td>
      <td>${decisionPill(record.decision)}</td>
      <td class="mono small">${escapeHtml(record.action)}</td>
      <td class="small">${escapeHtml(record.actorType)}:<span class="mono">${escapeHtml(record.actorId)}</span></td>
      <td class="small">${escapeHtml(record.reason)}</td>
      <td class="small mono audit-detail">${escapeHtml(record.appId ?? '—')}${record.sessionId ? `<div class="muted">${escapeHtml(record.sessionId.slice(0, 22))}…</div>` : ''}</td>
      <td class="mono small muted">${escapeHtml(record.hash.slice(0, 12))}…</td>
    </tr>`)
    .join('');

  const form = `
<form method="get" action="/admin/audit" class="actions-row" style="margin-bottom:14px">
  <input name="action" placeholder="action (e.g. app.access)" value="${escapeHtml(options.action ?? '')}" style="padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:var(--panel-2);color:var(--fg)">
  <input name="deviceId" placeholder="device id" value="${escapeHtml(options.deviceId ?? '')}" style="padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:var(--panel-2);color:var(--fg)">
  <select name="decision" style="padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:var(--panel-2);color:var(--fg)">
    <option value="">any decision</option>
    <option value="allow"${options.decision === 'allow' ? ' selected' : ''}>allow</option>
    <option value="deny"${options.decision === 'deny' ? ' selected' : ''}>deny</option>
    <option value="info"${options.decision === 'info' ? ' selected' : ''}>info</option>
  </select>
  <button class="btn" type="submit">Filter</button>
  <a class="btn" href="/admin/audit/export">Export JSONL</a>
</form>`;

  const body = `
<h1>Audit log</h1>
<p class="lede">Hash-chained, newest first. Each record commits to its predecessor; anchors are HMAC-signed every 64 records.</p>
<div class="alert ${chain.ok ? 'ok' : 'error'}">Chain verification: ${escapeHtml(chain.message)}${chain.brokenAt !== null ? ` (broken at #${chain.brokenAt})` : ''}</div>
${form}
<section class="panel"><div class="tablewrap"><table>
  <thead><tr><th>#</th><th>Time</th><th>Decision</th><th>Action</th><th>Actor</th><th>Reason</th><th>Context</th><th>Hash</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="8" class="muted">no records</td></tr>'}</tbody>
</table></div></section>`;
  return adminLayout(ctx, 'Audit', body);
}
