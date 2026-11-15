/**
 * Shared layout and small view helpers for the proxy's own pages.
 * Everything is server-rendered HTML with no third-party assets, so the CSP
 * can stay strict.
 */
import { escapeHtml } from '../respond.ts';

export interface LayoutOptions {
  title: string;
  nonce: string;
  body: string;
  /** Extra head content for page-specific inline styles. */
  head?: string;
  /** Whether to show the operator navigation. */
  operator?: boolean;
  /** Small status line in the header right corner. */
  badge?: string;
  /** Revalidation interval shown in the footer, in seconds. */
  revalidateSeconds?: number;
}

const BASE_STYLE = `
:root {
  color-scheme: dark;
  --bg: #0b1017;
  --panel: #121a25;
  --panel-2: #0f1620;
  --line: #223043;
  --fg: #dbe6f3;
  --muted: #8395ab;
  --accent: #4cc2ff;
  --allow: #3ddc97;
  --deny: #ff6b6b;
  --warn: #ffcc5c;
  font-family: ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: radial-gradient(1200px 600px at 20% -10%, #16233a 0%, var(--bg) 55%);
  color: var(--fg);
  min-height: 100vh;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 24px max(16px, env(safe-area-inset-left)) 64px max(16px, env(safe-area-inset-right)); }
header.top { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; margin-bottom: 20px; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 650; letter-spacing: 0.01em; }
.brand .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 12px var(--accent); }
nav { display: flex; flex-wrap: wrap; gap: 4px; }
nav a { padding: 6px 10px; border-radius: 8px; color: var(--muted); font-size: 0.9rem; }
nav a:hover, nav a.active { background: var(--panel); color: var(--fg); text-decoration: none; }
h1 { font-size: 1.5rem; margin: 0 0 4px; }
h2 { font-size: 1.1rem; margin: 0 0 12px; }
p.lede { color: var(--muted); margin: 0 0 24px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 20px; }
.grid { display: grid; gap: 16px; }
.grid.two { grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr)); }
.grid.three { grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr)); }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 550; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; }
tr:last-child td { border-bottom: none; }
.tablewrap { overflow-x: auto; }
.pill { display: inline-flex; align-items: center; gap: 5px; padding: 2px 9px; border-radius: 999px; font-size: 0.76rem; font-weight: 600; border: 1px solid var(--line); white-space: nowrap; }
.pill.allow { color: var(--allow); border-color: color-mix(in srgb, var(--allow) 40%, transparent); background: color-mix(in srgb, var(--allow) 12%, transparent); }
.pill.deny { color: var(--deny); border-color: color-mix(in srgb, var(--deny) 40%, transparent); background: color-mix(in srgb, var(--deny) 12%, transparent); }
.pill.warn { color: var(--warn); border-color: color-mix(in srgb, var(--warn) 40%, transparent); background: color-mix(in srgb, var(--warn) 10%, transparent); }
.pill.neutral { color: var(--muted); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.82rem; word-break: break-all; }
.muted { color: var(--muted); }
.small { font-size: 0.82rem; }
button, input[type=submit] { font: inherit; cursor: pointer; }
.btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 14px; border-radius: 9px; border: 1px solid var(--line); background: var(--panel-2); color: var(--fg); font-weight: 560; }
.btn:hover { border-color: var(--accent); }
.btn.primary { background: color-mix(in srgb, var(--accent) 18%, transparent); border-color: var(--accent); }
.btn.danger { border-color: color-mix(in srgb, var(--deny) 60%, transparent); color: var(--deny); }
form.inline { display: inline; }
.field { display: flex; flex-direction: column; gap: 6px; margin-bottom: 14px; }
.field label { font-size: 0.85rem; color: var(--muted); }
.field input { padding: 10px 12px; border-radius: 9px; border: 1px solid var(--line); background: var(--panel-2); color: var(--fg); font-size: 1rem; }
.field input:focus { outline: 2px solid color-mix(in srgb, var(--accent) 50%, transparent); border-color: var(--accent); }
.alert { padding: 10px 14px; border-radius: 10px; margin-bottom: 16px; font-size: 0.9rem; }
.alert.error { background: color-mix(in srgb, var(--deny) 12%, transparent); border: 1px solid color-mix(in srgb, var(--deny) 40%, transparent); color: var(--deny); }
.alert.ok { background: color-mix(in srgb, var(--allow) 12%, transparent); border: 1px solid color-mix(in srgb, var(--allow) 40%, transparent); color: var(--allow); }
.code { background: var(--panel-2); border: 1px solid var(--line); border-radius: 10px; padding: 12px; font-family: ui-monospace, monospace; font-size: 0.82rem; white-space: pre-wrap; word-break: break-word; }
details summary { cursor: pointer; color: var(--muted); }
footer { margin-top: 32px; color: var(--muted); font-size: 0.8rem; }
`;

export function layout(options: LayoutOptions): string {
  const nav = options.operator
    ? `<nav>
        <a href="/console">Console</a>
        <a href="/admin">Admin</a>
        <a href="/admin/devices">Devices</a>
        <a href="/admin/policy">Policy</a>
        <a href="/admin/audit">Audit</a>
      </nav>`
    : '';
  const badge = options.badge ? `<span class="muted small">${escapeHtml(options.badge)}</span>` : '';
  const interval = options.revalidateSeconds ?? 10;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${escapeHtml(options.title)} · Zero Trust Access</title>
<style>${BASE_STYLE}${options.head ?? ''}</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div class="brand"><span class="dot"></span> Zero Trust Access</div>
  <div style="display:flex;align-items:center;gap:14px">${badge}${nav}</div>
</header>
${options.body}
<footer>Every decision is written to the hash-chained audit log. Live sessions re-evaluate every ${interval}s and immediately on posture change.</footer>
</div>
</body>
</html>`;
}

/** Renders a posture requirement list as compact pills. */
export function requirementPills(requirements: { name: string; ok: boolean; detail: string }[]): string {
  if (requirements.length === 0) return '<span class="muted small">no checks</span>';
  return requirements
    .map(
      (requirement) =>
        `<span class="pill ${requirement.ok ? 'allow' : 'deny'}" title="${escapeHtml(requirement.detail)}">${escapeHtml(requirement.name)}${requirement.ok ? '' : ' ✕'}</span>`,
    )
    .join(' ');
}

export function decisionPill(decision: 'allow' | 'deny' | 'info'): string {
  const label = decision === 'allow' ? 'allow' : decision === 'deny' ? 'deny' : 'info';
  const css = decision === 'allow' ? 'allow' : decision === 'deny' ? 'deny' : 'neutral';
  return `<span class="pill ${css}">${label}</span>`;
}

export function relativeTime(date: string | Date | null, now = new Date()): string {
  if (date === null) return '—';
  const at = typeof date === 'string' ? new Date(date) : date;
  if (Number.isNaN(at.getTime())) return '—';
  const seconds = Math.round((now.getTime() - at.getTime()) / 1000);
  if (Math.abs(seconds) < 5) return 'just now';
  const past = seconds > 0;
  const value = Math.abs(seconds);
  let amount: number;
  let unit: string;
  if (value < 60) {
    amount = value;
    unit = 'second';
  } else if (value < 3600) {
    amount = Math.floor(value / 60);
    unit = 'minute';
  } else if (value < 86400) {
    amount = Math.floor(value / 3600);
    unit = 'hour';
  } else {
    amount = Math.floor(value / 86400);
    unit = 'day';
  }
  return `${past ? '' : 'in '}${amount} ${unit}${amount === 1 ? '' : 's'}${past ? ' ago' : ''}`;
}
