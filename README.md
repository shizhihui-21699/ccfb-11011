# Zero-trust access proxy — operator quick start

Replaces the VPN: every request is authenticated by **device certificate**,
**user login**, and **live posture**, then authorized per application, with
revocation inside a 60-second SLA and a hash-chained audit trail.

Full design and threat model: [DESIGN.md](./DESIGN.md).

## Requirements

- Node.js **24+** (tested on 26; uses native `.ts` execution and `node:sqlite`)
- OpenSSL on `PATH` — only to bootstrap the PKI

No runtime dependencies. TypeScript and `@types/node` are dev-only.

## Run

```bash
npm install            # typescript + node types (dev only)
npm run pki:init       # root CA → device CA / server CA → proxy cert + 3 device certs
npm run demo           # mock apps + posture service + proxy
```

Open <https://127.0.0.1:8443/>. The proxy requires a client certificate on
**every** request. Browsers that support certificate selection will prompt;
otherwise import a bundle from `pki/devices/` (PKCS#12 password `changeit`).

| Demo user | Certificate                                    | Group       | Posture                            |
| --------- | ---------------------------------------------- | ----------- | ---------------------------------- |
| alice     | `pki/devices/dev-alice-mbp/*.p12`              | engineering | healthy, admin role                |
| bob       | `pki/devices/dev-bob-win/*.p12`                | finance     | healthy                            |
| carol     | `pki/devices/dev-carol-mbp/*.p12`              | engineering | **stale**, disk unencrypted, EDR off |

Passwords live in `config/zero-trust.json` (demo only — replace for anything
real). alice/bob/carol passwords start with the username, e.g.
`alice-demo-password`.

The posture simulator at <http://127.0.0.1:9200/> can flip a device's state:
`POST /v1/devices/<id>/state` with `{"edr":"off"}`, `{"diskEncrypted":false}`,
`{"osVersion":"13.0.0"}` — watch access get cut within a second.

## What is enforced

1. **mTLS device identity** — the device id comes from the certificate's SAN
   URI `urn:zt:device:<id>`; a certificate not signed by the device CA, out of
   its validity window, missing clientAuth EKU, or unregistered is refused with
   an audited 401.
2. **User login bound to the device** — scrypt password check, rate limited per
   (user, device). The session cookie is AES-GCM sealed with the device id and
   certificate fingerprint as AAD, so it cannot be replayed from another device
   or after a certificate re-issue.
3. **Posture** — OS version, disk encryption, EDR online, firewall, freshness.
   Stale or missing posture fails closed. Version floors are **per OS family**;
   a family with no configured floor cannot be verified and is denied.
4. **Per-application policy** — declarative rules, first match wins, default
   deny; a bad policy file is rejected and the previous policy stays in force.
5. **Continuous authorization** — every active grant is re-evaluated every 10s
   and immediately on posture push; downgraded grants and sessions are revoked
   (measured ~1s in the demo, SLA 60s). The request path also re-checks.
6. **Audit** — hash-chained, HMAC-anchored, exported as JSONL.
7. **Admin console** at `/admin` (admin role): fleet posture, policy view,
   live sessions/grants, and the audit log with chain verification.

## Configuration

`config/zero-trust.json` (see `config/schema.json`):

| Field | Meaning |
| ----- | ------- |
| `port` / `host` | TLS listener (default `127.0.0.1:8443`) |
| `pkiDir` | trust material directory (default `pki/`) |
| `dbPath` | SQLite file (default `.zt/zero-trust.db`) |
| `sessionTtlSeconds` / `grantTtlSeconds` | session and per-app grant lifetimes |
| `thresholds.postureMaxAgeSeconds` | posture freshness limit (fail closed beyond) |
| `thresholds.minOsVersion` | per-family minimum OS versions |
| `thresholds.revalidateIntervalMs` | continuous re-evaluation period |
| `thresholds.revokeWithinMs` | SLA target surfaced in the admin console |
| `apps[]` | `{id, name, upstream, description}` |

`config/policy.json` (see `config/policy.schema.json`): ordered rules with
`effect`, `apps`, subject conditions (`users`, `groups`, `roles`,
`deviceGroups`, `deviceIds`) and posture requirements
(`requireDiskEncrypted`, `requireEdrOnline`, `requireFirewall`,
`osFamilies`, `minOsVersion`, `maxPostureAgeSeconds`). Policy hot-reloads.

Environment overrides: `ZT_CONFIG`, `ZT_HOST`, `ZT_PORT`, `ZT_PKI_DIR`,
`ZT_DB_PATH`, `ZT_SESSION_SECRET` (set explicitly in production — otherwise one
is generated into `.zt/session-secret`), `ZT_POLICY`, `ZT_POSTURE_URL`
(point at a real posture service), `ZT_TRUST_PROXY=1` (behind a load balancer).

## Verify

```bash
npm test          # 78 tests: policy, versions, audit chain, certificates,
                  # crypto, access control, revalidation, real-TLS end-to-end
npm run typecheck # strict TypeScript, noEmit
```

The end-to-end suite (`tests/http.test.ts`) builds a real PKI, a real posture
service, a mock upstream and the TLS proxy, then exercises: no-certificate
rejection, login, cookie replay from another device, per-app policy, a live
posture downgrade cutting access, header injection to upstream, cookie/Location
rewriting, admin role enforcement, and audit-chain integrity.

## Rotating trust material

```bash
npm run pki:init -- --force   # new CAs and device certs; invalidates old ones
```

Devices are imported from `pki/devices.json` at first boot. Revoking a device
is `deviceStore.revoke(id, at, reason)` — the proxy then refuses its certificate
on every request and the revalidator kills its sessions.
