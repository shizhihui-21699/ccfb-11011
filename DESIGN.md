# Design: zero-trust access proxy

## Why this exists

The internal apps used to sit behind a VPN. The VPN authenticates a *network
position*, then trusts everything from that IP. This proxy instead authenticates
three distinct things on every request — **device**, **user**, **posture** —
and re-checks them while the session is live.

```
             ┌──────────────┐
  browser ──▶ │ TLS (mTLS)   │  device certificate → device id
             └──────┬───────┘
                    ▼
             ┌──────────────┐   password + scrypt   ┌────────────┐
             │ access proxy │ ────────────────────▶ │ users (DB) │
             └──┬────┬───┬──┘                       └────────────┘
                │    │   └──────────────▶ policy engine (config/policy.json)
                │    └──────────────────▶ posture cache ◀── posture service
                │                              ▲            (simulated locally)
                ├──────────────────────────────┘
                ▼
         audit log (hash-chained)
                │
                ▼
       upstream internal apps
```

## Trust boundaries

| What | Where it comes from | Can the client lie? |
| ---- | ----------------- | ------------------- |
| Device identity | SAN URI `urn:zt:device:<id>` in the client certificate, verified against the device CA | No — the proxy reads the certificate, not request data |
| User identity | password login, bound to the certificate's device | Only with the password; the session is then sealed to that device |
| Posture | posture service API (agent telemetry) | Not through the proxy — the proxy never accepts posture from the browser |
| Authorization | `config/policy.json` evaluated server-side | No |

**Device identity never travels in a header or a cookie.** The device id is
extracted from the TLS peer certificate after signature, issuer, validity-window
and extended-key-usage checks. If the certificate is missing or invalid the
request is answered with an auditable `401` — the TLS layer is deliberately set
to `rejectUnauthorized: false` so that an invalid certificate produces a logged
decision instead of an unexplainable handshake reset. This is safe only because
verification happens before routing on *every* request (see
`src/pki/trust.ts`, `verifyClientCertificate`).

## Authentication chain

1. **TLS client certificate** signed by the **device CA** (separate from the
   server CA), with `extendedKeyUsage=clientAuth` and a SAN URI carrying the
   device id. Certificates are short-lived (90 days in the demo); a re-issued
   certificate gets a new fingerprint, which invalidates sessions sealed under
   the old one.
2. **Password login** (scrypt, parameterised hashes). Rate-limited per
   `(username, device)` pair through a persisted failure table.
3. **Session cookie** — AES-256-GCM sealed, with the device id *and* the
   certificate fingerprint as additional authenticated data. Copying a cookie
   to another machine's TLS connection fails to decrypt. A stolen cookie is
   useless without the corresponding private key.
4. **Device grant** — the device row is bound to its certificate fingerprint.
   A certificate that was never registered, or one re-issued for a revoked
   device, cannot authenticate even though it is validly signed by the CA.

## Authorization model

Two layers, both must pass:

**Device baseline (cannot be relaxed by policy).** Posture exists, is no older
than `postureMaxAgeSeconds`, reports disk encryption and a live EDR. Failing it
is a *device-wide* signal: every session and grant on the device is revoked.

**Application policy (declarative, hot-reloaded).** Rules are evaluated in
order, first applicable rule wins, no match = deny. A rule applies only if the
subject match (users/groups/roles/device groups/device ids) and all posture
requirements pass. Because evaluation stops at the first applicable rule, a
`deny` rule placed above permissive rules is a real carve-out. Malformed policy
files are rejected and the previous policy stays in force — a bad edit can never
silently widen access.

Rules may tighten *or* be stricter than the baseline, never looser.
`allowMissingPosture` exists for special cases but applies only inside the
policy layer; the baseline still fails closed.

### OS version floors are per family

Version numbering is not comparable across operating systems: macOS `15.2.0`,
Windows `11.0.22631`, Linux `6.8.0`. A single "minimum OS version" applied to a
mixed fleet is a real bug — an early iteration of this implementation denied a
fully patched Windows 11 machine because `11.0.22631 < 14.0.0` was evaluated as
a macOS floor. Floors are therefore maps:

```json
{ "macos": "14.0.0", "windows": "10.0.19045", "linux": "5.15.0" }
```

A bare string is still accepted for single-OS fleets, but a family with **no
configured floor cannot be verified and fails closed**.

## Continuous authorization

A background loop (`src/core/revalidator.ts`) walks every active grant on an
interval (`revalidateIntervalMs`, default 10 s) and re-runs the full decision
against the current posture snapshot. Anything that no longer qualifies is
revoked; device-wide failures cascade to every session on the device.

The posture service also pushes changes over server-sent events. A push triggers
an immediate pass for that device, so revocation does not wait for the next tick.
Measured end-to-end in the demo: **~1 second** from posture change to access cut,
against a 60-second SLA.

Belt and braces: the request path calls `checkGrantNow` before every proxied
request, so even in the window between a change and the next pass a revoked
grant cannot be used.

Fail-closed everywhere: an evaluator exception revokes the grant; stale or
missing posture is denied; a broken policy file keeps the last good policy.

## Session and grant lifecycle

- Session created at login, TTL `sessionTtlSeconds`, sealed to
  (device id, certificate fingerprint).
- One **grant per (session, application)**, TTL `grantTtlSeconds`, independently
  revocable.
- Logout revokes the session and its grants.
- Revocation cascades: session → grants; device trust failure → all sessions on
  the device.
- A session presented from a different device, or with a re-issued
  certificate, is refused and audited as a mismatch.

## Audit

Every security-relevant event is appended to a SQLite table with a
**SHA-256 hash chain**: each record commits to its predecessor's hash, so
deleting or editing history breaks verification. Every 64 records an **HMAC
anchor** is written with a key derived from the session secret; rewriting an
anchored head fails verification even if the chain is recomputed internally.
`/admin/audit` shows the verification result and exports JSONL for SIEM.

Recorded: mTLS rejections, login attempts (with reason), session creation /
revocation / expiry, grant creation / revocation, every proxied request, every
denial with decision code and per-requirement results, revalidation passes,
device and certificate mismatches, admin access denials, upstream failures.

## Admin console

`/admin` — fleet posture overview, last revalidation pass, posture-service sync
health, SLAs, and recent decisions.
`/admin/devices` — certificate fingerprints, expiry, owner, posture per device.
`/admin/policy` — the policy as the engine sees it, plus load errors.
`/admin/sessions` — live sessions and grants with last evaluation.
`/admin/audit` — filterable, hash-chain verification, JSONL export.

All admin pages require an authenticated session with the `admin` role, and the
denial is audited.

## Deliberate simplifications (lab scope)

These are real for a demo, and would change for production:

- **PKI keys on disk.** Root and issuing CA keys are unencrypted files in
  `pki/`. Production: HSM-backed issuing CA, device keys in TPM/Secure Enclave,
  OCSP/CRL for revocation rather than only the local device table.
- **Posture service is unauthenticated locally.** The simulator accepts unauthenticated
  `PUT`s from `127.0.0.1`. Production: agents sign telemetry, the service verifies
  agent identity.
- **Password login.** Real deployments would use SSO (OIDC/SAML) with
  device-bound tokens; the device binding would still come from mTLS.
- **Session cookie is stateless-sealed plus server-side state.** The sealed
  cookie carries the session id; the record is authoritative.
- **Single process.** SQLite + an in-process revalidator. Multi-instance would
  need shared session store and a distributed revocation channel.
- **No CRL/OCSP.** Certificate revocation is enforced through the device row
  (`status='revoked'`), which the proxy checks on every request.
- **Admin routes are read-only in the UI.** Revoking a device/exporting is
  supported through the data layer and CLI/API shape, not wired to POST
  handlers.
- **Demo passwords in config.** `config/zero-trust.json` contains cleartext
  demo passwords; seeding hashes them at first boot.

## Files

```
src/
  main.ts                 process entry
  config.ts               env + JSON config, secret resolution, validation
  crypto/{hash,password,seal}.ts
  pki/trust.ts            certificate verification, SAN parsing
  policy/{engine,store}.ts  rule evaluation, hot reload
  core/{runtime,access,sessions,revalidator}.ts
  store/{db,repositories,audit,types}.ts
  services/{posture-service,posture-sync}.ts
  http/{server,auth,proxy,respond}.ts
  http/views/{layout,login,console,admin,errors}.ts
scripts/{pki,demo,mock-apps,config-schema}.ts
config/{zero-trust.json,policy.json,schema.json,policy.schema.json}
tests/*.test.ts           78 tests incl. real-TLS end-to-end
```
