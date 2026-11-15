#!/usr/bin/env -S node
/**
 * Operator CLI. Runs against the same database as the proxy, so it is meant
 * for local/ops use (the admin console is deliberately read-only).
 *
 *   node scripts/admin.ts devices
 *   node scripts/admin.ts revoke <deviceId> --reason "lost laptop"
 *   node scripts/admin.ts enroll <deviceId> <cert.pem> --owner alice --group engineering
 *   node scripts/admin.ts sessions
 *   node scripts/admin.ts revoke-session <sessionId> --reason "incident"
 *   node scripts/admin.ts audit verify
 *   node scripts/admin.ts audit export > audit.jsonl
 *   node scripts/admin.ts revalidate
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import { loadConfig } from '../src/config.ts';
import { createRuntime } from '../src/core/runtime.ts';
import { formatFingerprint, normalizeFingerprint } from '../src/pki/trust.ts';

const USAGE = `usage:
  devices
  enroll <deviceId> <cert.pem> [--owner <username>] [--group <group>] [--name "<display name>"]
  revoke <deviceId> [--reason "<text>"]
  sessions
  revoke-session <sessionId> [--reason "<text>"]
  audit verify
  audit export [--limit <n>]
  revalidate`;

function flag(args: string[], name: string): string | undefined {
  const index = args.indexOf(`--${name}`);
  if (index === -1) return undefined;
  return args[index + 1];
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  if (command === undefined) {
    console.log(USAGE);
    process.exitCode = 2;
    return;
  }
  const config = loadConfig();
  const runtime = await createRuntime({ config, postureBaseUrl: null, logger: () => {}, seed: false });
  try {
    switch (command) {
      case 'devices': {
        const rows = runtime.devices.list();
        if (rows.length === 0) console.log('no devices registered');
        for (const device of rows) {
          console.log(`${device.id}  ${device.status}`);
          console.log(`  name     ${device.displayName}`);
          console.log(`  owner    ${device.ownerUserId ?? '—'}  group ${device.group ?? '—'}`);
          console.log(`  serial   ${device.certSerial}`);
          console.log(`  sha256   ${formatFingerprint(device.certFingerprint256)}`);
          console.log(`  expires  ${device.certExpiresAt}`);
          if (device.revokedAt !== null) console.log(`  revoked  ${device.revokedAt} (${device.revokedReason})`);
        }
        break;
      }
      case 'enroll': {
        const [deviceId, certPath] = rest;
        if (deviceId === undefined || certPath === undefined) {
          console.error('enroll requires <deviceId> <cert.pem>');
          process.exitCode = 2;
          return;
        }
        const pem = fs.readFileSync(certPath, 'utf8');
        const cert = new crypto.X509Certificate(pem);
        // Refuse to register anything the proxy would not accept anyway.
        if (!cert.checkIssued(runtime.trust.deviceCa) || !cert.verify(runtime.trust.deviceCa.publicKey)) {
          throw new Error('certificate is not signed by the configured device CA');
        }
        const sans = (cert.subjectAltName ?? '')
          .split(',')
          .map((part) => part.trim())
          .filter((part) => part.startsWith('URI:'))
          .map((part) => part.slice(4));
        if (!sans.includes(`urn:zt:device:${deviceId}`)) {
          throw new Error(`certificate does not carry urn:zt:device:${deviceId}`);
        }
        const ownerUsername = flag(rest, 'owner');
        const owner = ownerUsername === undefined ? null : (runtime.users.findByUsername(ownerUsername)?.id ?? null);
        if (ownerUsername !== undefined && owner === null) {
          throw new Error(`no such user "${ownerUsername}"`);
        }
        const fingerprint = normalizeFingerprint(cert.fingerprint256);
        if (runtime.devices.findByFingerprint(fingerprint) !== null) {
          throw new Error('this certificate is already registered');
        }
        const now = new Date().toISOString();
        runtime.devices.upsert({
          id: deviceId,
          displayName: flag(rest, 'name') ?? deviceId,
          ownerUserId: owner,
          group: flag(rest, 'group') ?? null,
          certSerial: cert.serialNumber.toLowerCase(),
          certFingerprint256: fingerprint,
          certIssuedAt: cert.validFromDate.toISOString(),
          certExpiresAt: cert.validToDate.toISOString(),
          status: 'enrolled',
          enrolledAt: now,
          revokedAt: null,
          revokedReason: null,
          lastSeenAt: null,
        });
        runtime.audit.append({
          actorType: 'admin',
          actorId: process.env.USER ?? 'cli',
          action: 'device.enrolled',
          decision: 'info',
          reason: 'Device certificate registered by operator.',
          deviceId,
          userId: owner,
          detail: { fingerprint, serial: cert.serialNumber.toLowerCase() },
        });
        console.log(`enrolled ${deviceId} (${formatFingerprint(fingerprint)})`);
        break;
      }
      case 'revoke': {
        const deviceId = rest[0];
        if (deviceId === undefined) {
          console.error('revoke requires <deviceId>');
          process.exitCode = 2;
          return;
        }
        const device = runtime.devices.findById(deviceId);
        if (device === null) throw new Error(`no such device "${deviceId}"`);
        const reason = flag(rest, 'reason') ?? 'revoked by operator';
        const now = new Date();
        runtime.devices.revoke(deviceId, now.toISOString(), reason);
        runtime.audit.append({
          actorType: 'admin',
          actorId: process.env.USER ?? 'cli',
          action: 'device.revoked',
          decision: 'info',
          reason,
          deviceId,
        });
        // Revoke its live sessions immediately rather than waiting for a pass.
        let sessions = 0;
        for (const session of runtime.sessions.listActive().filter((entry) => entry.deviceId === deviceId)) {
          if (runtime.sessionManager.revokeSession(session, `device revoked: ${reason}`, now, { type: 'admin', id: process.env.USER ?? 'cli' })) {
            sessions += 1;
          }
        }
        console.log(`revoked ${deviceId}; ${sessions} session(s) terminated`);
        break;
      }
      case 'sessions': {
        for (const session of runtime.sessions.listActive()) {
          const grants = runtime.grants.listForSession(session.id).filter((grant) => grant.state === 'active');
          console.log(`${session.id}  user=${session.userId}  device=${session.deviceId}`);
          console.log(`  ip=${session.ip}  expires=${session.expiresAt}`);
          console.log(`  grants=${grants.map((grant) => grant.appId).join(',') || '—'}`);
        }
        if (runtime.sessions.countActive() === 0) console.log('no active sessions');
        break;
      }
      case 'revoke-session': {
        const sessionId = rest[0];
        if (sessionId === undefined) {
          console.error('revoke-session requires <sessionId>');
          process.exitCode = 2;
          return;
        }
        const session = runtime.sessions.findById(sessionId);
        if (session === null) throw new Error(`no such session "${sessionId}"`);
        const reason = flag(rest, 'reason') ?? 'revoked by operator';
        runtime.sessionManager.revokeSession(session, reason, new Date(), {
          type: 'admin',
          id: process.env.USER ?? 'cli',
        });
        console.log(`revoked ${sessionId}`);
        break;
      }
      case 'audit': {
        const sub = rest[0];
        if (sub === 'verify') {
          const result = runtime.audit.verify();
          console.log(result.message);
          if (!result.ok) process.exitCode = 1;
          return;
        }
        if (sub === 'export') {
          const limit = Number(flag(rest, 'limit') ?? 5000);
          process.stdout.write(`${runtime.audit.toJsonl(Number.isFinite(limit) ? limit : 5000)}\n`);
          return;
        }
        throw new Error('audit requires "verify" or "export"');
      }
      case 'revalidate': {
        const report = await runtime.revalidator.runOnce('cli');
        console.log(JSON.stringify(report, null, 2));
        break;
      }
      default:
        console.error(`unknown command "${command}"\n${USAGE}`);
        process.exitCode = 2;
    }
  } finally {
    await runtime.shutdown();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
