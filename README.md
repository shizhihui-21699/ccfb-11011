# Zero-trust access proxy

A TypeScript replacement for VPN access to internal systems. Users sign in with
a directory account, the device presents a client certificate carrying a device
ID, and the proxy decides every request from **who** the user is, **which**
device they are on, and **how healthy** that device currently is. When a device
degrades, existing sessions are revoked within a policy-defined SLA (60s by
default) — not on the next request, but from a background enforcement pass.

```
                        ┌───────────────────────────────┐
   browser ──mTLS──►    │  access proxy (src/server.ts) │  ──► upstream app
   (device cert)        │                               │      (identity headers)
                        │  1 certificate → device id    │
                        │  2 session + user identity    │
                        │  3 policy: host/path → app    │
                        │  4 posture pull + evaluate    │
                        └───────────────┬───────────────┘
                                        │ pulls posture (service token)
                             ┌──────────▼──────────┐
                             │  posture service    │◄── reports (per-device token)
                             │  (separate process) │        from device agents
                             └─────────────────────┘

                        ┌───────────────────────────────┐
                        │  session enforcer (in proxy)  │
                        │  re-evaluates every live      │
                        │  session every 5s → revoke    │
                        └───────────────────────────────┘
```

## Quick start

Requires Node 24+ (native TypeScript execution) and `openssl` on `PATH`.

```bash
npm install
npm run setup -- --force    # internal CA, server cert, one client cert per device,
                            # user directory, agent tokens, seeded posture
npm run dev                 # posture service + mock upstream + agents + proxy
```

Then:

- Console: <https://localhost:8443/_zta/> — needs a client certificate.
- Sign in as `alice` with the device certificate `certs/devices/dev-alice-macbook.crt`
  and key `certs/devices/dev-alice-macbook.key`. Passwords are generated into
  `data/demo-credentials.json` (mode `0600`).
- Application: <https://localhost:8443/wiki/page> (proxied to the mock upstream).

With curl:

```bash
PW=$(python3 -c "import json;print(json.load(open('data/demo-credentials.json'))['alice'])")
CERT="--cert certs/devices/dev-alice-macbook.crt --key certs/devices/dev-alice-macbook.key --cacert certs/ca.crt"

# 1. get the sign-in page and its CSRF token
curl -s -c /tmp/jar $CERT https://localhost:8443/_zta/login -o /tmp/login.html
CSRF=$(grep -o 'name="csrf" value="[^"]*"' /tmp/login.html | sed 's/.*value="//;s/"//')

# 2. sign in
curl -s -b /tmp/jar -c /tmp/jar $CERT -X POST https://localhost:8443/_zta/login \
  --data-urlencode "username=alice" --data-urlencode "password=$PW" --data-urlencode "csrf=$CSRF"

# 3. call an application through the proxy
curl -s -b /tmp/jar $CERT https://localhost:8443/wiki/page
```

Run the whole scenario automatically (offline, temporary state):

```bash
npm run demo       # 11 end-to-end checks
npm test           # unit + integration tests
npm run typecheck
```

## How the pieces fit

| Path | Responsibility |
| --- | --- |
| `src/config.ts` | Loads and **validates** `config/policy.json`; rejects unsafe/ambiguous policy at startup |
| `src/auth/deviceIdentity.ts` | Reads the device id from the certificate SAN URI `urn:zta:device:<id>` (never from CN) |
| `src/auth/sessionStore.ts` | Server-side sessions; only SHA-256 hashes of cookie tokens are stored |
| `src/policy/engine.ts` | Host/path → app selection, RBAC, posture merge, decision assembly |
| `src/posture/evaluate.ts` | Pure posture evaluation (version, disk, EDR, heartbeat age, freshness) |
| `src/posture/cache.ts` | Pulls posture from the posture service with a short TTL and coalescing |
| `src/enforcement.ts` | Background re-evaluation of live sessions → revocation + audit |
| `src/http/proxy.ts` | Streams requests upstream, strips inbound `X-ZTA-*`, injects asserted identity |
| `src/audit.ts` | Append-only hash-chained audit log with tamper verification |
| `src/postureService.ts` | Separate service that accepts simulated posture reports |
| `src/views.ts` | Server-rendered admin/self-service console |
| `scripts/setup.ts` | Generates the lab PKI, users, device registry, agent tokens |
| `scripts/device-agent.ts` | Simulated on-device agent (can degrade itself on purpose) |

## Trust boundaries and key decisions

**Certificates.** The proxy's TLS listener requests a client certificate against
our CA (`ca: certs/ca.crt`). `rejectUnauthorized: false` at the handshake is
deliberate: certificate-less clients must be able to reach `/_zta/login`, which
tells them *why* they are refused. Every other route requires a verified peer
certificate, and the device id comes from the SAN URI — not from the CN, which
is user-visible and easy to collide. A certificate must additionally match the
fingerprint enrolled in `data/devices.json`, and a session is bound to the exact
certificate that created it: replaying a session cookie from a different
machine (with a different — even valid — certificate) is refused and the
session is killed.

**Posture is never taken from the request.** The proxy pulls posture from the
posture service with a bearer token it alone holds. Agents report to the
posture service with a per-device token, so one device cannot report for
another. The proxy has no write path into posture data. The posture service
stamps `reportedAt` itself on receipt (and clamps the EDR heartbeat to "not in
the future"), so a lying or badly-skewed agent clock cannot make an old report
look fresh.

**Fail closed.** No report, a report older than `maxReportAgeSeconds`, an
unparsable OS version, an unreachable posture service — all deny. A short grace
period serves the last snapshot during a brief outage, but a sustained one
revokes.

**Continuous authorization.** The enforcer walks every live session every
`postureRecheckSeconds` (default 5s) regardless of traffic, so a device that
degrades while idle still loses access. Policy validation refuses a
`revocationSlaSeconds` that is not comfortably larger than the recheck interval.
Revoked sessions are never resurrected, even if posture recovers — the user
signs in again.

**Sessions** are server-side, `HttpOnly; Secure; SameSite=Strict; __Host-`
cookies. Only the hash of the token is kept, so a heap dump or log leak does not
yield usable tokens. Sign-in is rate-limited per (user, device, IP).

**Audit** is append-only JSON Lines where each record contains the hash of the
previous record. `verifyChain()` runs on every console view and health check, so
editing or deleting a record is visible. Every allow, deny, login, revocation and
admin action is recorded with the reason codes that drove it.

**Upstream identity.** Inbound `X-ZTA-*` headers are stripped (they are
client-controlled). The proxy sets `X-ZTA-User`, `X-ZTA-Groups`,
`X-ZTA-Device`, `X-ZTA-Posture`, `X-ZTA-Posture-Score`, `X-ZTA-App`,
`X-ZTA-Session` and `X-Request-Id`, so upstreams can trust them. Policy
`injectHeaders` cannot override reserved headers — the policy validator rejects
that.

**Path agreement.** A prefix policy is only as strong as the proxy and the
upstream agreeing on the path. `resolveRequestPath()` rejects encoded path
separators (`%2F`, `%5C`), encoded dots and control characters, double
encoding, and dot segments; the request forwarded upstream is rebuilt from the
decoded path the policy matched, so an upstream cannot decode its way into a
scope the policy never evaluated. Host values are matched after lowercasing and
stripping the port, so `Host: wiki.x:8443` cannot pick a different app than
`Host: wiki.x`.

## Policy format

`config/policy.json` is validated at startup (`src/config.ts`). Unknown
platforms, empty `allow` blocks, an empty `hosts` list, `file:` upstreams,
duplicate app ids, reserved headers and a recheck interval that is not below
the revocation SLA are all startup errors rather than runtime surprises.

```json
{
  "version": 1,
  "settings": {
    "sessionTtlMinutes": 480,
    "idleTimeoutMinutes": 30,
    "postureRecheckSeconds": 5,
    "postureCacheSeconds": 2,
    "revocationSlaSeconds": 60,
    "requireDeviceAssignedToUser": true,
    "loginRateLimit": { "maxFailures": 5, "windowSeconds": 300, "lockoutSeconds": 300 }
  },
  "postureBaseline": {
    "minOsVersion": { "darwin": "14.0", "win32": "10.0.19045", "linux": "12.0" },
    "requireDiskEncryption": true,
    "requireEdrInstalled": true,
    "requireEdrRunning": true,
    "maxEdrHeartbeatAgeSeconds": 15,
    "maxReportAgeSeconds": 60
  },
  "apps": [
    {
      "id": "finance-dashboard",
      "description": "Finance reporting — stricter device posture",
      "upstream": "http://127.0.0.1:8461",
      "hosts": ["finance.zta.local", "localhost"],
      "paths": ["/finance"],
      "allow": { "groups": ["finance", "ops"] },
      "require": { "posture": { "maxEdrHeartbeatAgeSeconds": 10, "minScore": 95 } },
      "maxSessionMinutes": 60,
      "methods": ["GET", "POST"],
      "injectHeaders": { "X-Auth-Realm": "employees" }
    }
  ]
}
```

Semantics:

- **App selection** is by host (`"*"` alone matches any host; otherwise `*`
  matches within a single label) and longest matching path prefix. The method is
  checked *after* specificity is decided, so a stricter child path cannot be
  bypassed by a broader parent that accepts every method.
- **Authorization**: `allow.users` / `allow.groups` — either match grants access.
- **Posture**: per-app `require.posture` is merged over `postureBaseline`, field
  by field, with the app value winning. An explicit `false` is an override, not
  "absent".
- **`maxSessionMinutes`** caps how old a session may be for that app; this is
  enforced per request, not by tearing down unrelated sessions.
- **Enforcement scope**: the baseline applies to every session. App-specific
  posture requirements apply only to apps the session actually reached, which
  keeps one app's strictness from killing sessions that never touched it.

## Posture evaluation

Each requirement contributes to a 0-100 score; any failed requirement makes the
device `degraded` and is returned as a reason code:

| Check | Code | Weight |
| --- | --- | --- |
| No report / report too old | `posture.missing`, `posture.stale_report` | status `unknown`, score 0 |
| Full-disk encryption | `posture.disk_not_encrypted` | 20 |
| EDR installed | `posture.edr_missing` | 20 |
| EDR running | `posture.edr_stopped` | 25 |
| OS ≥ minimum for platform | `posture.os_outdated`, `posture.os_unparsable` | 20 |
| EDR heartbeat fresh | `posture.edr_offline`, `posture.edr_no_heartbeat` | 10 |
| Report freshness (< 6h) | `posture.report_old` | 5 |
| Optional `minScore` floor | `posture.score_below_minimum` | — |

A boolean `edrRunning` is not trusted on its own: the heartbeat timestamp is
what proves the agent is actually reporting, so an EDR that was killed while
still claiming `running: true` goes stale and fails.

## Admin console

`/_zta/` is available to every signed-in user (their own devices and sessions);
admins additionally see all devices, all sessions, per-session kill, device
revoke/restore, the full audit log and the audit chain status. Revoking a device
also kills its sessions immediately — this does not wait for the enforcer pass.

## Simulated posture reporting

`npm run dev` starts one agent per seed device. To break a device on purpose,
stop the dev stack and run an agent with flags (or set the equivalent env vars
`ZTA_AGENT_*`):

```bash
npm run agent -- --device dev-alice-macbook --edr off          # watch the session die
npm run agent -- --device dev-alice-macbook --disk plaintext
npm run agent -- --device dev-alice-macbook --os 13.6
npm run agent -- --device dev-alice-macbook --heartbeat-stale
npm run agent -- --device dev-alice-macbook --once             # single report
```

Directly, against the posture service:

```bash
TOKEN=$(cat data/posture-token.txt)
curl -s -H "authorization: Bearer $TOKEN" http://127.0.0.1:8450/v1/posture/dev-alice-macbook
```

## Configuration reference (environment)

| Variable | Default | Meaning |
| --- | --- | --- |
| `ZTA_HOST` / `ZTA_PORT` | `127.0.0.1` / `8443` | Proxy listener |
| `ZTA_CERT_DIR` | `./certs` | CA, server cert and per-device certs |
| `ZTA_DATA_DIR` | `./data` | Users, devices, audit, tokens |
| `ZTA_POLICY_FILE` | `./config/policy.json` | Policy |
| `ZTA_POSTURE_URL` | `http://127.0.0.1:8450` | Posture service base URL |
| `ZTA_POSTURE_TOKEN` / `ZTA_POSTURE_TOKEN_FILE` | `data/posture-token.txt` | Proxy→posture bearer token |
| `ZTA_AGENT_TOKENS_FILE` | `data/agent-tokens.json` | Per-device agent tokens |
| `ZTA_UPSTREAM_TIMEOUT_MS` | `15000` | Upstream request timeout |
| `ZTA_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |

## Tests

`npm test` covers:

- `tests/util.test.ts` — host/path matching (including prefix-boundary and
  wildcard-label rules), version comparison, cookies, redirect sanitization,
  encoded-path/traversal rejection
- `tests/posture.test.ts` — every posture failure mode, fail-closed behaviour,
  `minScore`, heartbeat-vs-boolean, report validation and clock trust
- `tests/policy.test.ts` — app selection, RBAC, requirement merging, session-age
  caps, policy validation rejections
- `tests/enforcement.test.ts` — revocation on EDR stop / stale heartbeat /
  unencrypted disk / missing report / posture outage / device revocation /
  certificate change; revocation with no device traffic; per-app scope; no
  duplicate audits; non-overlapping passes
- `tests/session.test.ts` — session lifecycle, hashed tokens, revocation,
  expiry reaping, rate limiting
- `tests/audit.test.ts` — hash chain, tamper detection, deletion detection

`npm run demo` runs the full stack (real TLS with client certificates, real
posture service, mock upstream) and asserts the end-to-end behaviours,
including the revocation latency versus the 60s SLA.

## What is out of scope for this lab

- The user directory is local (`data/users.json`, scrypt). The proxy only
  depends on the `AuthenticatedUser` shape, so an OIDC/SAML verifier can replace
  `UserStore` without touching policy or enforcement.
- The posture service is local and accepts simulated reports. Real deployments
  would source these from EDR/MDM APIs and sign the reports.
- Certificates are generated by `scripts/setup.ts` into `certs/`, which is
  gitignored. **Never reuse these keys outside a lab.**
- No CRL/OCSP: revocation is enforced by registry status and fingerprint
  checks at the proxy, which is what makes it fast; producing a CRL for other
  consumers would be an additional step.
- Audit records are hash-chained but not signed or shipped to remote WORM
  storage; `verifyChain()` detects tampering with the local file.
