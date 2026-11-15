import { escapeHtml } from '../respond.ts';
import { layout } from './layout.ts';

const STYLE = `
.err { max-width: 640px; margin: 8vh auto 0; }
.err h1 { font-size: 1.6rem; }
.err ul { color: var(--muted); font-size: 0.88rem; line-height: 1.7; }
`;

/**
 * Shown when a request has no valid device certificate, or an admin page is
 * reached by a non-admin. Deliberately spells out what the proxy checked, so
 * a misconfigured client can fix itself without operator help.
 */
export function unauthenticatedPage(options: { reason: string; failure: string | null }): string {
  const hints: Record<string, string> = {
    no_certificate: 'This browser did not present a client certificate for this site.',
    not_device_ca_issued: 'The certificate was not issued by this organisation’s device CA.',
    signature_invalid: 'The certificate signature could not be verified against the device CA.',
    expired: 'The device certificate has expired. Re-enroll the device.',
    not_yet_valid: 'The device certificate’s validity window has not started yet.',
    wrong_key_usage: 'The certificate lacks the TLS client-authentication extended key usage.',
    missing_device_id: 'The certificate carries no device identifier (SAN URI urn:zt:device:<id>).',
    malformed_device_id: 'The certificate’s device identifier is malformed.',
  };
  const detail = options.failure === null ? '' : hints[options.failure] ?? '';
  const body = `
<main class="err">
  <div class="panel">
    <h1>Device certificate required</h1>
    <div class="alert error">${escapeHtml(options.reason)}</div>
    ${detail ? `<p class="muted">${escapeHtml(detail)}</p>` : ''}
    <ul>
      <li>Every request must arrive over TLS with a client certificate signed by the device CA.</li>
      <li>The device identity comes from the certificate’s <span class="mono">urn:zt:device:</span> SAN — it cannot be supplied by the client.</li>
      <li>Import your device bundle on the login page, restart the browser, and reload this page.</li>
    </ul>
    <p><a class="btn" href="/login">Continue to sign in</a></p>
  </div>
</main>`;
  return layout({ title: 'Certificate required', nonce: '', body, head: STYLE });
}

export function errorPage(title: string, detail: string): string {
  const body = `
<main class="err">
  <div class="panel">
    <h1>${escapeHtml(title)}</h1>
    <div class="alert error">${escapeHtml(detail)}</div>
    <p><a class="btn" href="/console">Back to console</a></p>
  </div>
</main>`;
  return layout({ title, nonce: '', body, head: STYLE });
}
