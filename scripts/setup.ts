/**
 * One-shot environment setup for the local demo / test environment.
 *
 * Creates:
 *   certs/            internal CA, TLS server cert, one client cert per device
 *   data/users.json   demo user directory (random passwords)
 *   data/devices.json device registry (fingerprints bound to certificates)
 *   data/agent-tokens.json, data/posture-token.txt
 *   data/demo-credentials.json (mode 0600) so the demo scripts can sign in
 *
 * Everything is local-only. CA private keys are written to certs/ which is
 * gitignored: never reuse these certificates outside a lab.
 */
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { hashPassword } from '../src/password.ts';
import type { DeviceRecord, DeviceRegistryFile, UserDirectoryFile } from '../src/types.ts';
import { nowIso } from '../src/util.ts';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CERTS = join(ROOT, 'certs');
const DEVICE_CERTS = join(CERTS, 'devices');
const DATA = join(ROOT, 'data');

interface SeedDevice {
  id: string;
  label: string;
  platform: 'darwin' | 'win32' | 'linux';
  assignedTo: string;
  /** Simulated initial posture, reported by the device agent. */
  posture: {
    osVersion: string;
    diskEncrypted: boolean;
    edrInstalled: boolean;
    edrRunning: boolean;
    edrOnline: boolean;
  };
}

export const SEED_DEVICES: SeedDevice[] = [
  {
    id: 'dev-alice-macbook',
    label: "Alice's MacBook Pro",
    platform: 'darwin',
    assignedTo: 'alice',
    posture: { osVersion: '15.1.0', diskEncrypted: true, edrInstalled: true, edrRunning: true, edrOnline: true },
  },
  {
    id: 'dev-bob-thinkpad',
    label: "Bob's ThinkPad",
    platform: 'win32',
    assignedTo: 'bob',
    posture: { osVersion: '10.0.22631', diskEncrypted: true, edrInstalled: true, edrRunning: true, edrOnline: true },
  },
  {
    id: 'dev-carol-linux',
    label: "Carol's workstation (non-compliant)",
    platform: 'linux',
    assignedTo: 'carol',
    posture: { osVersion: '12.5.0', diskEncrypted: false, edrInstalled: true, edrRunning: false, edrOnline: false },
  },
  {
    id: 'dev-admin-mac',
    label: 'IT admin console',
    platform: 'darwin',
    assignedTo: 'admin',
    posture: { osVersion: '15.1.0', diskEncrypted: true, edrInstalled: true, edrRunning: true, edrOnline: true },
  },
];

const SEED_USERS = [
  { id: 'alice', displayName: 'Alice Nguyen', groups: ['engineering'], role: 'user' as const },
  { id: 'bob', displayName: 'Bob Martinez', groups: ['engineering', 'finance'], role: 'user' as const },
  { id: 'carol', displayName: 'Carol Osei', groups: ['engineering'], role: 'user' as const },
  { id: 'dave', displayName: 'Dave Kim', groups: ['contractors'], role: 'user' as const },
  { id: 'admin', displayName: 'IT Administrator', groups: ['ops'], role: 'admin' as const },
];

function run(args: string[], cwd = CERTS): string {
  return execFileSync('openssl', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function opensslAvailable(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function randomPassword(): string {
  // Ambiguous characters removed so operators can copy them reliably.
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = randomBytes(20);
  let out = '';
  for (const byte of bytes) out += alphabet[byte % alphabet.length];
  return out;
}

function fingerprint(certPath: string): string {
  const output = run(['x509', '-in', certPath, '-noout', '-fingerprint', '-sha256']);
  const match = /Fingerprint=([0-9A-Fa-f:]+)/.exec(output);
  if (!match) throw new Error(`could not read fingerprint from ${certPath}`);
  return match[1].toUpperCase();
}

function certNotAfter(certPath: string): string {
  return run(['x509', '-in', certPath, '-noout', '-enddate'])
    .replace('notAfter=', '')
    .trim();
}

function subjectOf(certPath: string): string {
  return run(['x509', '-in', certPath, '-noout', '-subject'])
    .replace('subject=', '')
    .trim();
}

function serialOf(certPath: string): string {
  return run(['x509', '-in', certPath, '-noout', '-serial'])
    .replace('serial=', '')
    .trim();
}

function makeCa(): void {
  run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'ca.key']);
  run([
    'req', '-x509', '-new', '-key', 'ca.key', '-sha256', '-days', '3650',
    '-out', 'ca.crt',
    '-subj', '/CN=ZTA Lab Internal CA/O=Zero Trust Lab',
    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
  ]);
  chmodSync(join(CERTS, 'ca.key'), 0o600);
}

function makeServerCert(): void {
  run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'server.key']);
  run(['req', '-new', '-key', 'server.key', '-out', 'server.csr', '-subj', '/CN=access-proxy.zta.local/O=Zero Trust Lab']);
  writeFileSync(
    join(CERTS, 'server.ext'),
    [
      'basicConstraints=critical,CA:FALSE',
      'keyUsage=critical,digitalSignature',
      'extendedKeyUsage=serverAuth',
      'subjectAltName=DNS:localhost,DNS:access-proxy.zta.local,IP:127.0.0.1,IP:::1',
      '',
    ].join('\n'),
  );
  run([
    'x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial',
    '-days', '825', '-sha256', '-extfile', 'server.ext', '-out', 'server.crt',
  ]);
  chmodSync(join(CERTS, 'server.key'), 0o600);
  rmSync(join(CERTS, 'server.csr'), { force: true });
  rmSync(join(CERTS, 'server.ext'), { force: true });
}

function makeDeviceCert(device: SeedDevice): { certPath: string; keyPath: string } {
  const certPath = join(DEVICE_CERTS, `${device.id}.crt`);
  const keyPath = join(DEVICE_CERTS, `${device.id}.key`);
  const base = join('devices', device.id);
  run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', `${base}.key`]);
  run([
    'req', '-new', '-key', `${base}.key`, '-out', `${base}.csr`,
    '-subj', `/CN=${device.id}/O=Zero Trust Lab`,
  ]);
  const extPath = join(DEVICE_CERTS, `${device.id}.ext`);
  writeFileSync(
    extPath,
    [
      'basicConstraints=critical,CA:FALSE',
      'keyUsage=critical,digitalSignature',
      'extendedKeyUsage=clientAuth',
      // The device id is carried as a SAN URI, not as the CN: the proxy reads
      // only this value as identity.
      `subjectAltName=URI:urn:zta:device:${device.id},DNS:${device.id}`,
      '',
    ].join('\n'),
  );
  run([
    'x509', '-req', '-in', `${base}.csr`, '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAserial', 'ca.srl',
    '-days', '365', '-sha256', '-extfile', `devices/${device.id}.ext`, '-out', base + '.crt',
  ]);
  chmodSync(keyPath, 0o600);
  rmSync(join(DEVICE_CERTS, `${device.id}.csr`), { force: true });
  rmSync(extPath, { force: true });
  return { certPath, keyPath };
}

export function simulateFacts(device: SeedDevice) {
  const now = Date.now();
  return {
    osVersion: device.posture.osVersion,
    diskEncrypted: device.posture.diskEncrypted,
    edrInstalled: device.posture.edrInstalled,
    edrRunning: device.posture.edrRunning,
    edrLastHeartbeatAt: device.posture.edrOnline ? new Date(now).toISOString() : new Date(now - 45 * 60_000).toISOString(),
    agentVersion: '1.4.2',
    reportedAt: new Date(now).toISOString(),
    source: 'simulator' as const,
  };
}

export function setup(): void {
  if (!opensslAvailable()) throw new Error('openssl is required to generate the lab certificates');
  mkdirSync(CERTS, { recursive: true });
  mkdirSync(DEVICE_CERTS, { recursive: true });
  mkdirSync(DATA, { recursive: true });

  // Fresh PKI each run, so fingerprints recorded in devices.json always match
  // the certificates currently on disk.
  for (const file of ['ca.crt', 'ca.key', 'ca.srl', 'server.crt', 'server.key']) {
    rmSync(join(CERTS, file), { force: true });
  }
  for (const device of SEED_DEVICES) {
    for (const ext of ['crt', 'key']) rmSync(join(DEVICE_CERTS, `${device.id}.${ext}`), { force: true });
  }

  makeCa();
  makeServerCert();

  const devices: DeviceRecord[] = [];
  const agentTokens: Record<string, string> = {};

  for (const device of SEED_DEVICES) {
    const { certPath, keyPath } = makeDeviceCert(device);
    agentTokens[device.id] = randomBytes(24).toString('base64url');
    devices.push({
      id: device.id,
      label: device.label,
      platform: device.platform,
      assignedTo: device.assignedTo,
      status: 'active',
      certFingerprint256: fingerprint(certPath),
      certSubject: subjectOf(certPath),
      certSerial: serialOf(certPath),
      certNotAfter: certNotAfter(certPath),
      certPath: resolve(certPath),
      keyPath: resolve(keyPath),
      enrolledAt: nowIso(),
    });
  }

  const credentials: Record<string, string> = {};
  const users = SEED_USERS.map((user) => {
    const password = randomPassword();
    credentials[user.id] = password;
    return { ...user, passwordHash: hashPassword(password) };
  });

  const registry: DeviceRegistryFile = { version: 1, devices };
  const directory: UserDirectoryFile = { version: 1, users };
  writeFileSync(join(DATA, 'devices.json'), `${JSON.stringify(registry, null, 2)}\n`);
  writeFileSync(join(DATA, 'users.json'), `${JSON.stringify(directory, null, 2)}\n`);
  writeFileSync(join(DATA, 'agent-tokens.json'), `${JSON.stringify({ version: 1, tokens: agentTokens }, null, 2)}\n`);
  chmodSync(join(DATA, 'agent-tokens.json'), 0o600);
  writeFileSync(join(DATA, 'posture-token.txt'), `${randomBytes(32).toString('base64url')}\n`);
  chmodSync(join(DATA, 'posture-token.txt'), 0o600);
  writeFileSync(join(DATA, 'demo-credentials.json'), `${JSON.stringify(credentials, null, 2)}\n`);
  chmodSync(join(DATA, 'demo-credentials.json'), 0o600);

  // Seed the posture service with each device's simulated starting state.
  writeFileSync(
    join(DATA, 'posture.json'),
    `${JSON.stringify(
      {
        version: 1,
        records: SEED_DEVICES.map((device) => ({
          deviceId: device.id,
          facts: simulateFacts(device),
          updatedAt: nowIso(),
          revision: 1,
        })),
      },
      null,
      2,
    )}\n`,
  );

  console.log('Setup complete.\n');
  console.log(`  CA certificate      ${join(CERTS, 'ca.crt')}`);
  console.log(`  Server certificate  ${join(CERTS, 'server.crt')}`);
  console.log(`  Devices             ${devices.map((device) => device.id).join(', ')}`);
  console.log(`  Users               ${users.map((user) => `${user.id} (${user.role})`).join(', ')}`);
  console.log(`  Demo passwords      ${join(DATA, 'demo-credentials.json')} (mode 0600)`);
  console.log('\nStart the posture service and the proxy, then open https://localhost:8443/_zta/login');
  console.log('with a device certificate, e.g. curl --cert certs/devices/dev-alice-macbook.crt \\');
  console.log('  --key certs/devices/dev-alice-macbook.key --cacert certs/ca.crt https://localhost:8443/_zta/login');
  if (!existsSync(join(ROOT, 'config', 'policy.json'))) {
    console.log('\nWARNING: config/policy.json is missing; the proxy will refuse to start.');
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  // Re-running is safe and rotates every credential and certificate.
  if (process.argv.includes('--force') || !existsSync(join(DATA, 'users.json'))) {
    setup();
  } else {
    console.log('data/users.json already exists; re-run with --force to rotate certificates and credentials.');
  }
}
