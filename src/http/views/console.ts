/**
 * The signed-in console: application launcher and per-application access
 * status, plus the denial page used by the proxy when policy refuses.
 */
import type { AppDefinition } from '../../config.ts';
import type { GrantRecord, SessionRecord, UserRecord } from '../../store/types.ts';
import type { RequirementResult } from '../../policy/engine.ts';
import { escapeHtml } from '../respond.ts';
import { layout, requirementPills } from './layout.ts';

const STYLE = `
.app-grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr)); }
.app-card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 18px; display: flex; flex-direction: column; gap: 10px; }
.app-card h3 { margin: 0; font-size: 1rem; }
.app-card p { margin: 0; color: var(--muted); font-size: 0.86rem; flex: 1; }
.app-card .actions { display: flex; align-items: center; gap: 10px; justify-content: space-between; }
.session-strip { display: flex; flex-wrap: wrap; gap: 18px; font-size: 0.85rem; color: var(--muted); }
.session-strip div { display: flex; flex-direction: column; gap: 2px; }
.session-strip strong { color: var(--fg); font-weight: 600; font-size: 0.82rem; }
.req { display: flex; flex-wrap: wrap; gap: 6px; }
`;

export interface ConsoleAppView {
  app: AppDefinition;
  status: 'granted' | 'available' | 'denied' | 'error';
  detail: string;
  requirements: RequirementResult[];
  grantExpiresAt: string | null;
}

export function consolePage(options: {
  nonce: string;
  user: UserRecord;
  session: SessionRecord;
  device: { deviceId: string; fingerprint256: string; validTo: Date };
  apps: ConsoleAppView[];
  posture: {
    osName: string;
    osVersion: string;
    diskEncrypted: boolean;
    edrOnline: boolean;
    edrProduct: string;
    collectedAt: string;
  } | null;
  revalidateSeconds: number;
  flash?: { kind: 'ok' | 'error'; text: string } | null;
  signedOutNotice?: boolean;
}): string {
  const postureAge =
    options.posture === null
      ? 'none'
      : `${Math.max(0, Math.round((Date.now() - new Date(options.posture.collectedAt).getTime()) / 1000))}s ago`;
  const cards = options.apps
    .map((entry) => {
      const { app, status, detail, requirements } = entry;
      const pill =
        status === 'granted'
          ? '<span class="pill allow">granted</span>'
          : status === 'available'
            ? '<span class="pill neutral">check required</span>'
            : status === 'error'
              ? '<span class="pill warn">error</span>'
              : '<span class="pill deny">denied</span>';
      const action =
        status === 'denied'
          ? `<span class="muted small">${escapeHtml(detail)}</span>`
          : `<a class="btn ${status === 'granted' ? '' : 'primary'}" href="/app/${escapeHtml(app.id)}/">Open</a>`;
      return `
<article class="app-card">
  <div class="actions"><h3>${escapeHtml(app.name)}</h3>${pill}</div>
  <p>${escapeHtml(app.description ?? '')}</p>
  ${requirements.length > 0 ? `<div class="req">${requirementPills(requirements)}</div>` : ''}
  ${status === 'denied' ? '' : `<div class="muted small">${escapeHtml(detail)}</div>`}
  <div class="actions">${action}${entry.grantExpiresAt ? `<span class="muted small">until ${escapeHtml(entry.grantExpiresAt.slice(11, 19))}Z</span>` : ''}</div>
</article>`;
    })
    .join('');

  const postureBlock =
    options.posture === null
      ? '<span class="pill deny">no posture</span>'
      : `<span class="pill ${options.posture.diskEncrypted ? 'allow' : 'deny'}">disk ${options.posture.diskEncrypted ? 'encrypted' : 'unencrypted'}</span>
         <span class="pill ${options.posture.edrOnline ? 'allow' : 'deny'}">EDR ${options.posture.edrOnline ? 'online' : 'offline'}</span>
         <span class="pill neutral">${escapeHtml(options.posture.osName)} ${escapeHtml(options.posture.osVersion)}</span>
         <span class="muted small">collected ${escapeHtml(postureAge)}</span>`;

  const body = `
<h1>Console</h1>
<p class="lede">Signed in as <strong>${escapeHtml(options.user.displayName)}</strong> (${escapeHtml(options.user.username)}). Access is decided per application and re-checked live.</p>
${options.flash ? `<div class="alert ${options.flash.kind}">${escapeHtml(options.flash.text)}</div>` : ''}
${options.signedOutNotice ? '<div class="alert ok">You have been signed out.</div>' : ''}
<section class="panel" style="margin-bottom:20px">
  <h2>This device</h2>
  <div class="session-strip">
    <div><strong>Device</strong><span class="mono">${escapeHtml(options.device.deviceId)}</span></div>
    <div><strong>Certificate SHA-256</strong><span class="mono">${escapeHtml(options.device.fingerprint256.slice(0, 32))}…</span></div>
    <div><strong>Cert expires</strong><span>${escapeHtml(options.device.validTo.toISOString().slice(0, 10))}</span></div>
    <div><strong>Session</strong><span class="mono">${escapeHtml(options.session.id.slice(0, 18))}…</span></div>
  </div>
  <div class="req" style="margin-top:14px">${postureBlock}</div>
</section>
<h2>Applications</h2>
<div class="app-grid" style="margin-bottom:24px">${cards}</div>
<form method="post" action="/logout"><button class="btn danger" type="submit">Sign out</button></form>`;

  return layout({
    title: 'Console',
    nonce: options.nonce,
    body,
    head: STYLE,
    operator: true,
    badge: `reval ${options.revalidateSeconds}s`,
    revalidateSeconds: options.revalidateSeconds,
  });
}

export function accessDeniedPage(options: {
  app: AppDefinition;
  code: string;
  reason: string;
  requirements: RequirementResult[];
  session: SessionRecord;
}): string {
  const body = `
<h1>Access denied</h1>
<p class="lede">Policy refused <strong>${escapeHtml(options.app.name)}</strong> for this session and device.</p>
<section class="panel" style="max-width:720px">
  <div class="alert error">${escapeHtml(options.reason)}</div>
  <table>
    <tr><th>Decision code</th><td class="mono">${escapeHtml(options.code)}</td></tr>
    <tr><th>Application</th><td>${escapeHtml(options.app.name)} (<span class="mono">${escapeHtml(options.app.id)}</span>)</td></tr>
    <tr><th>Session</th><td class="mono">${escapeHtml(options.session.id)}</td></tr>
  </table>
  <h2 style="margin-top:18px">Checks</h2>
  <div class="req">${requirementPills(options.requirements)}</div>
  <p class="muted small" style="margin-top:16px">This decision was audited. If your device changed state, reconnect after it is remediated.</p>
  <p style="margin-top:18px"><a class="btn" href="/console">Back to console</a></p>
</section>`;
  return layout({ title: 'Access denied', nonce: '', body });
}

/** Lists the grants belonging to one session, for the console summary. */
export function summarizeGrants(grants: GrantRecord[]): string {
  if (grants.length === 0) return '<span class="muted small">no application grants yet</span>';
  return grants
    .map((grant) => `<span class="mono small">${escapeHtml(grant.appId)}:${grant.state}</span>`)
    .join(' ');
}
