import type { ClientIdentity } from '../../pki/trust.ts';
import { escapeHtml } from '../respond.ts';
import { layout } from './layout.ts';

export interface LoginPageOptions {
  nonce: string;
  next: string | null;
  device: ClientIdentity;
  error?: string;
}

const STYLE = `
.login-wrap { max-width: 460px; margin: 8vh auto 0; }
.device-card { background: var(--panel-2); border: 1px solid var(--line); border-radius: 12px; padding: 14px; margin-bottom: 20px; }
.device-card .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin-bottom: 6px; }
.device-card .value { font-family: ui-monospace, monospace; font-size: 0.9rem; }
.device-card .fp { color: var(--muted); font-size: 0.76rem; margin-top: 8px; word-break: break-all; }
@media (max-width: 480px) { .login-wrap { margin-top: 3vh; } }
`;

export function loginPage(options: LoginPageOptions): string {
  const device = options.device;
  const fingerprint = device.fingerprint256.match(/.{2}/g)?.slice(0, 8).join(':') ?? '';
  const nextField =
    options.next === null ? '' : `<input type="hidden" name="next" value="${escapeHtml(options.next)}">`;
  const body = `
<main class="login-wrap">
  <div class="panel">
    <h1>Sign in</h1>
    <p class="lede">Your device certificate was accepted. Confirm your identity to continue.</p>
    ${options.error ? `<div class="alert error">${escapeHtml(options.error)}</div>` : ''}
    <div class="device-card">
      <div class="label">Device certificate</div>
      <div class="value">${escapeHtml(device.deviceId)}</div>
      ${device.userHint ? `<div class="value" style="margin-top:6px">user hint: ${escapeHtml(device.userHint)}</div>` : ''}
      <div class="fp">SHA-256 ${escapeHtml(fingerprint)}…<br>expires ${escapeHtml(device.validTo.toISOString().slice(0, 10))}</div>
    </div>
    <form method="post" action="/login">
      ${nextField}
      <input type="hidden" name="nonce" value="${escapeHtml(options.nonce)}">
      <div class="field">
        <label for="username">Username</label>
        <input id="username" name="username" autocomplete="username" required autofocus>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
      </div>
      <button class="btn primary" type="submit" style="width:100%;justify-content:center">Sign in</button>
    </form>
  </div>
</main>`;
  return layout({ title: 'Sign in', nonce: options.nonce, body, head: STYLE });
}
