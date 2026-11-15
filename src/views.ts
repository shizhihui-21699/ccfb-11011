/**
 * Server-rendered admin console. No client framework: the page is a snapshot,
 * refreshed by reloading, so it cannot drift from server state.
 */
import type { AuditEntry } from './audit.ts';
import type { AppPolicy, PostureRequirements, SessionView } from './types.ts';
import { escapeHtml as h } from './http/httpUtil.ts';

export const BASE_STYLE = `
  :root { color-scheme: light dark; --bg:#fafafa; --panel:#fff; --fg:#18181b; --muted:#6b7280;
          --line:#e4e4e7; --ok:#15803d; --warn:#b45309; --bad:#b91c1c; --accent:#4338ca; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#111114; --panel:#1a1a1f; --fg:#e4e4e7; --muted:#9ca3af; --line:#2e2e36;
            --ok:#4ade80; --warn:#fbbf24; --bad:#f87171; --accent:#818cf8; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif; }
  header { padding:16px 24px; border-bottom:1px solid var(--line); background:var(--panel);
           display:flex; gap:16px; align-items:center; flex-wrap:wrap; }
  header h1 { font-size:16px; margin:0; font-weight:650; letter-spacing:-0.01em; }
  header .who { margin-left:auto; color:var(--muted); font-size:13px; }
  main { padding:24px; max-width:1180px; margin:0 auto; display:grid; gap:20px; }
  section { background:var(--panel); border:1px solid var(--line); border-radius:10px; overflow:hidden; }
  section > h2 { font-size:13px; text-transform:uppercase; letter-spacing:0.06em; color:var(--muted);
                 margin:0; padding:14px 16px; border-bottom:1px solid var(--line); font-weight:600; }
  .pad { padding:16px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:0.04em; }
  tr:last-child td { border-bottom:0; }
  code, .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }
  .tag { display:inline-block; padding:1px 7px; border-radius:999px; font-size:11px; font-weight:600;
         border:1px solid currentColor; }
  .ok { color:var(--ok); } .warn { color:var(--warn); } .bad { color:var(--bad); }
  .muted { color:var(--muted); }
  .muted-s { color:var(--muted); font-size:12px; }
  form.inline { display:inline; margin:0; }
  button { font:inherit; font-size:12px; padding:3px 10px; border-radius:6px; border:1px solid var(--line);
           background:var(--panel); color:var(--fg); cursor:pointer; }
  button:hover { border-color:var(--accent); }
  button.danger { color:var(--bad); border-color:currentColor; }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
  @media (max-width: 820px) { .grid2 { grid-template-columns:1fr; } main { padding:14px; } }
  .kv { display:grid; grid-template-columns:minmax(120px,auto) 1fr; gap:6px 16px; font-size:13px; }
  .kv dt { color:var(--muted); } .kv dd { margin:0; }
  .scroll { overflow-x:auto; }
  .banner { border-radius:10px; padding:12px 16px; border:1px solid currentColor; font-size:13px; }
  ul.reasons { margin:6px 0 0; padding-left:18px; }
  ul.reasons li { margin:2px 0; }
`;

export function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${h(title)}</title><style>${BASE_STYLE}</style></head>
<body>${body}</body></html>`;
}

export function postForm(action: string, csrf: string, label: string, fields: Record<string, string> = {}, danger = false): string {
  const hidden = Object.entries({ ...fields, csrf })
    .map(([key, value]) => `<input type="hidden" name="${h(key)}" value="${h(value)}">`)
    .join('');
  return `<form class="inline" method="post" action="${h(action)}">${hidden}<button type="submit"${
    danger ? ' class="danger"' : ''
  }>${h(label)}</button></form>`;
}

export function statusTag(status: string): string {
  const cls = status === 'healthy' || status === 'active' ? 'ok' : status === 'degraded' ? 'warn' : 'bad';
  return `<span class="tag ${cls}">${h(status)}</span>`;
}

export interface DeviceRowView {
  id: string;
  label: string;
  platform: string;
  assignedTo: string;
  status: string;
  postureStatus: string;
  score: number | null;
  reasons: string[];
  osVersion: string | null;
  reportAgeSeconds: number | null;
  certNotAfter: string;
  fingerprint: string;
  sessions: number;
}

export function renderDeviceTable(rows: DeviceRowView[], csrf: string, isAdmin: boolean): string {
  if (rows.length === 0) return '<div class="pad muted">No devices enrolled.</div>';
  const body = rows
    .map(
      (row) => `<tr>
  <td><div><strong>${h(row.label)}</strong></div><code>${h(row.id)}</code>
      <div class="muted-s">cert exp ${h(row.certNotAfter)}</div></td>
  <td>${h(row.platform)}<div class="muted-s">${h(row.osVersion ?? 'no report')}</div></td>
  <td>${h(row.assignedTo)}</td>
  <td>${statusTag(row.status)}</td>
  <td>${statusTag(row.postureStatus)}${row.score !== null ? ` <span class="muted-s">${row.score}/100</span>` : ''}
    ${
      row.reasons.length > 0
        ? `<ul class="reasons">${row.reasons.map((reason) => `<li class="muted-s">${h(reason)}</li>`).join('')}</ul>`
        : ''
    }</td>
  <td class="muted-s">${row.reportAgeSeconds === null ? '—' : `${row.reportAgeSeconds}s ago`}</td>
  <td>${row.sessions}</td>
  <td>${
    !isAdmin
      ? ''
      : row.status === 'active'
        ? postForm(`/admin/devices/${encodeURIComponent(row.id)}/revoke`, csrf, 'Revoke', {}, true)
        : postForm(`/admin/devices/${encodeURIComponent(row.id)}/restore`, csrf, 'Restore')
  }</td>
</tr>`,
    )
    .join('\n');
  return `<div class="scroll"><table>
<thead><tr><th>Device</th><th>Platform</th><th>Assigned to</th><th>Status</th><th>Posture</th><th>Last report</th><th>Sessions</th><th></th></tr></thead>
<tbody>${body}</tbody></table></div>`;
}

export function renderSessions(sessions: SessionView[], csrf: string, isAdmin: boolean): string {
  if (sessions.length === 0) return '<div class="pad muted">No sessions.</div>';
  const rows = sessions
    .map((session) => {
      const revoked = session.revokedAt !== undefined;
      const live = !revoked;
      return `<tr>
  <td><code>${h(session.id)}</code></td>
  <td>${h(session.userId)}</td>
  <td><code>${h(session.deviceId)}</code></td>
  <td>${live ? '<span class="tag ok">live</span>' : `<span class="tag bad">revoked</span><div class="muted-s">${h(session.revokeReason ?? '')}</div>`}</td>
  <td class="muted-s">${session.ageSeconds}s / idle ${session.idleSeconds}s</td>
  <td class="muted-s">${session.apps.length ? session.apps.map((app) => h(app)).join(', ') : '—'}</td>
  <td>${isAdmin && live ? postForm(`/admin/sessions/${encodeURIComponent(session.id)}/revoke`, csrf, 'Kill', {}, true) : ''}</td>
</tr>`;
    })
    .join('\n');
  return `<div class="scroll"><table>
<thead><tr><th>Session</th><th>User</th><th>Device</th><th>State</th><th>Age</th><th>Apps used</th><th></th></tr></thead>
<tbody>${rows}</tbody></table></div>`;
}

export function renderApps(apps: readonly AppPolicy[], baseline: PostureRequirements, platformFor: (appId: string) => string): string {
  const rows = apps
    .map(
      (app) => `<tr>
  <td><strong>${h(app.id)}</strong>${app.description ? `<div class="muted-s">${h(app.description)}</div>` : ''}</td>
  <td class="mono">${h(app.hosts.join(', ') || '*')}<div class="muted-s">${h((app.paths ?? ['/']).join(', '))}</div></td>
  <td class="mono">${h(app.upstream)}</td>
  <td class="mono">${h([...(app.allow.users ?? []).map((u) => `user:${u}`), ...(app.allow.groups ?? []).map((g) => `group:${g}`)].join(', '))}</td>
  <td class="muted-s">${h(platformFor(app.id))}</td>
</tr>`,
    )
    .join('\n');
  return `<div class="scroll"><table>
<thead><tr><th>App</th><th>Host / path</th><th>Upstream</th><th>Allowed</th><th>Posture (effective)</th></tr></thead>
<tbody>${rows}</tbody></table></div>
<div class="pad muted-s">Baseline: ${h(describeRequirements(baseline))}</div>`;
}

export function describeRequirements(req: PostureRequirements): string {
  const parts: string[] = [];
  if (req.minOsVersion) {
    parts.push(
      `min OS ${Object.entries(req.minOsVersion)
        .map(([platform, version]) => `${platform} ${version}`)
        .join(', ')}`,
    );
  }
  if (req.requireDiskEncryption) parts.push('disk encryption');
  if (req.requireEdrInstalled) parts.push('EDR installed');
  if (req.requireEdrRunning) parts.push('EDR running');
  if (req.maxEdrHeartbeatAgeSeconds !== undefined) parts.push(`EDR heartbeat ≤ ${req.maxEdrHeartbeatAgeSeconds}s`);
  if (req.maxReportAgeSeconds !== undefined) parts.push(`report ≤ ${req.maxReportAgeSeconds}s`);
  if (req.minScore !== undefined) parts.push(`score ≥ ${req.minScore}`);
  return parts.length > 0 ? parts.join(' · ') : 'no additional requirements';
}

export function renderAudit(entries: AuditEntry[]): string {
  if (entries.length === 0) return '<div class="pad muted">No audit events yet.</div>';
  const rows = entries
    .map(
      (entry) => `<tr>
  <td class="muted-s">${h(entry.ts.replace('T', ' ').replace(/\..*$/, 'Z'))}</td>
  <td><code>${h(entry.event)}</code></td>
  <td>${tagOutcome(entry.outcome)}</td>
  <td class="muted-s">${h(entry.actor?.userId ?? '—')}<div>${h(entry.actor?.deviceId ?? '')}</div></td>
  <td class="muted-s">${h(entry.appId ?? '')}</td>
  <td>${h(entry.message ?? '')}${entry.reasonCodes?.length ? `<div class="muted-s mono">${h(entry.reasonCodes.join(', '))}</div>` : ''}</td>
</tr>`,
    )
    .join('\n');
  return `<div class="scroll"><table>
<thead><tr><th>Time</th><th>Event</th><th>Outcome</th><th>Actor</th><th>App</th><th>Detail</th></tr></thead>
<tbody>${rows}</tbody></table></div>`;
}

function tagOutcome(outcome: string): string {
  const cls = outcome === 'allow' ? 'ok' : outcome === 'deny' ? 'bad' : 'muted';
  return `<span class="tag ${cls}">${h(outcome)}</span>`;
}

export function pageHeader(title: string, who: string, csrf: string, isAdmin: boolean): string {
  return `<header>
  <h1>${h(title)}</h1>
  ${isAdmin ? '<span class="tag ok">admin</span>' : '<span class="tag muted">self-service</span>'}
  <span class="who">${h(who)}</span>
  ${postForm('/logout', csrf, 'Sign out')}
</header>`;
}
