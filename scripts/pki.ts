#!/usr/bin/env -S node
/**
 * Bootstraps the demo PKI with the OpenSSL CLI:
 *
 *   root-ca  ──┬── device-ca  ── client certs (one per demo device)
 *              └── server-ca  ── proxy.crt (the TLS listener)
 *
 * Device client certificates embed `urn:zt:device:<id>` in a SAN URI. The
 * proxy reads the device id from there, never from request data.
 *
 * Usage: node scripts/pki.ts init [--force]
 *        node scripts/pki.ts show
 */
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { randomSerial } from '../src/util/ids.ts';

const ROOT = path.resolve(import.meta.dirname, '..');
const PKI_DIR = path.resolve(ROOT, process.env.ZT_PKI_DIR ?? 'pki');

interface DemoDevice {
  id: string;
  displayName: string;
  ownerUsername: string | null;
  group: string;
  osName: string;
  osVersion: string;
  diskEncrypted: boolean;
  edrOnline: boolean;
  edrProduct: string;
  firewallEnabled: boolean;
  screenLockSeconds: number | null;
  patchLevel: string;
  /** Emit periodic agent reports (keeps posture fresh like a real fleet). */
  autoRefresh: boolean;
  /** How old the seeded posture report is, in seconds. */
  postureAgeSeconds: number;
}

export interface DeviceManifestEntry {
  id: string;
  displayName: string;
  ownerUsername: string | null;
  group: string;
  serial: string;
  fingerprint256: string;
  issuedAt: string;
  expiresAt: string;
  osName: string;
  osVersion: string;
  diskEncrypted: boolean;
  edrOnline: boolean;
  edrProduct: string;
  firewallEnabled: boolean;
  screenLockSeconds: number | null;
  patchLevel: string;
  autoRefresh: boolean;
  postureAgeSeconds: number;
}

const DEMO_DEVICES: DemoDevice[] = [
  {
    id: 'dev-alice-mbp',
    displayName: "Alice's MacBook Pro",
    ownerUsername: 'alice',
    group: 'engineering',
    osName: 'macOS',
    osVersion: '15.2.0',
    diskEncrypted: true,
    edrOnline: true,
    edrProduct: 'CrowdStrike Falcon',
    firewallEnabled: true,
    screenLockSeconds: 300,
    patchLevel: '2026-10-28',
    autoRefresh: true,
    postureAgeSeconds: 20,
  },
  {
    id: 'dev-bob-win',
    displayName: "Bob's ThinkPad",
    ownerUsername: 'bob',
    group: 'finance',
    osName: 'Windows',
    osVersion: '11.0.22631',
    diskEncrypted: true,
    edrOnline: true,
    edrProduct: 'Microsoft Defender for Endpoint',
    firewallEnabled: true,
    screenLockSeconds: 600,
    patchLevel: '2026-11-05',
    autoRefresh: true,
    postureAgeSeconds: 45,
  },
  {
    id: 'dev-carol-mbp',
    displayName: "Carol's MacBook Air",
    ownerUsername: 'carol',
    group: 'engineering',
    osName: 'macOS',
    osVersion: '13.6.1',
    diskEncrypted: false,
    edrOnline: false,
    edrProduct: 'CrowdStrike Falcon',
    firewallEnabled: true,
    screenLockSeconds: null,
    patchLevel: '2025-06-14',
    autoRefresh: false,
    // Deliberately stale: exercises the fail-closed path on first request.
    postureAgeSeconds: 60 * 60 * 6,
  },
];

function openssl(args: string[]): string {
  return execFileSync('openssl', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function fileExists(...segments: string[]): boolean {
  return fs.existsSync(path.join(PKI_DIR, ...segments));
}

function pkiPath(...segments: string[]): string {
  const target = path.join(PKI_DIR, ...segments);
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  return target;
}

function generateKey(relativePath: string): string {
  const keyFile = pkiPath(relativePath);
  openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', keyFile]);
  fs.chmodSync(keyFile, 0o600);
  return keyFile;
}

function makeCa(commonName: string, parent: { cert: string; key: string } | null, prefix: string): void {
  const keyPath = generateKey(`${prefix}.key`);
  const csr = path.join(PKI_DIR, `${prefix}.csr`);
  openssl(['req', '-new', '-key', keyPath, '-subj', `/CN=${commonName}`, '-out', csr]);
  const ext = path.join(PKI_DIR, `${prefix}.ext`);
  fs.writeFileSync(
    ext,
    [
      'basicConstraints=critical,CA:TRUE,pathlen:0',
      'keyUsage=critical,keyCertSign,cRLSign',
      'subjectKeyIdentifier=hash',
      '',
    ].join('\n'),
  );
  const certPath = path.join(PKI_DIR, `${prefix}.crt`);
  if (parent === null) {
    openssl([
      'x509', '-req', '-in', csr, '-signkey', keyPath,
      '-days', '3650', '-sha256', '-extfile', ext, '-out', certPath,
    ]);
  } else {
    openssl([
      'x509', '-req', '-in', csr,
      '-CA', parent.cert, '-CAkey', parent.key,
      '-set_serial', `0x${randomSerial()}`,
      '-days', '1825', '-sha256', '-extfile', ext, '-out', certPath,
    ]);
  }
  fs.rmSync(csr, { force: true });
  fs.rmSync(ext, { force: true });
  fs.chmodSync(certPath, 0o644);
}

function makeServerCert(): void {
  const keyPath = generateKey('proxy.key');
  const csr = path.join(PKI_DIR, 'proxy.csr');
  openssl(['req', '-new', '-key', keyPath, '-subj', '/CN=zero-trust-proxy', '-out', csr]);
  const ext = path.join(PKI_DIR, 'proxy.ext');
  fs.writeFileSync(
    ext,
    [
      'basicConstraints=critical,CA:FALSE',
      'keyUsage=critical,digitalSignature,keyEncipherment',
      'extendedKeyUsage=serverAuth',
      'subjectAltName=DNS:localhost,DNS:zero-trust-proxy,IP:127.0.0.1,IP:::1',
      'subjectKeyIdentifier=hash',
      'authorityKeyIdentifier=keyid,issuer',
      '',
    ].join('\n'),
  );
  openssl([
    'x509', '-req', '-in', csr,
    '-CA', path.join(PKI_DIR, 'server-ca.crt'),
    '-CAkey', path.join(PKI_DIR, 'server-ca.key'),
    '-set_serial', `0x${randomSerial()}`,
    '-days', '397', '-sha256', '-extfile', ext,
    '-out', path.join(PKI_DIR, 'proxy.crt'),
  ]);
  fs.rmSync(csr, { force: true });
  fs.rmSync(ext, { force: true });
  fs.chmodSync(path.join(PKI_DIR, 'proxy.crt'), 0o644);
}

function makeDeviceCert(device: DemoDevice): DeviceManifestEntry {
  const dir = `devices/${device.id}`;
  const keyPath = generateKey(`${dir}/${device.id}.key`);
  const csr = path.join(PKI_DIR, dir, `${device.id}.csr`);
  openssl([
    'req', '-new', '-key', keyPath,
    '-subj', `/CN=${device.id}/O=Zero Trust Demo`,
    '-out', csr,
  ]);
  const ext = path.join(PKI_DIR, dir, `${device.id}.ext`);
  fs.writeFileSync(
    ext,
    [
      'basicConstraints=critical,CA:FALSE',
      'keyUsage=critical,digitalSignature',
      'extendedKeyUsage=clientAuth',
      `subjectAltName=URI:urn:zt:device:${device.id},URI:urn:zt:user:${device.ownerUsername ?? 'unassigned'}`,
      'subjectKeyIdentifier=hash',
      'authorityKeyIdentifier=keyid,issuer',
      '',
    ].join('\n'),
  );
  const certPath = path.join(PKI_DIR, dir, `${device.id}.crt`);
  const serial = randomSerial();
  openssl([
    'x509', '-req', '-in', csr,
    '-CA', path.join(PKI_DIR, 'device-ca.crt'),
    '-CAkey', path.join(PKI_DIR, 'device-ca.key'),
    '-set_serial', `0x${serial}`,
    '-days', '90', '-sha256', '-extfile', ext,
    '-out', certPath,
  ]);
  // Bundle as PKCS#12 so browsers can import it.
  openssl([
    'pkcs12', '-export', '-inkey', keyPath, '-in', certPath,
    '-certfile', path.join(PKI_DIR, 'device-ca.crt'),
    '-name', device.id,
    '-passout', 'pass:changeit',
    '-out', path.join(PKI_DIR, dir, `${device.id}.p12`),
  ]);
  fs.chmodSync(path.join(PKI_DIR, dir, `${device.id}.p12`), 0o600);
  fs.rmSync(csr, { force: true });
  fs.rmSync(ext, { force: true });

  const x509 = new crypto.X509Certificate(fs.readFileSync(certPath));
  return {
    id: device.id,
    displayName: device.displayName,
    ownerUsername: device.ownerUsername,
    group: device.group,
    serial: x509.serialNumber.toLowerCase(),
    fingerprint256: x509.fingerprint256.replaceAll(':', '').toLowerCase(),
    issuedAt: x509.validFromDate.toISOString(),
    expiresAt: x509.validToDate.toISOString(),
    osName: device.osName,
    osVersion: device.osVersion,
    diskEncrypted: device.diskEncrypted,
    edrOnline: device.edrOnline,
    edrProduct: device.edrProduct,
    firewallEnabled: device.firewallEnabled,
    screenLockSeconds: device.screenLockSeconds,
    patchLevel: device.patchLevel,
    autoRefresh: device.autoRefresh,
    postureAgeSeconds: device.postureAgeSeconds,
  };
}

function init(force: boolean): void {
  if (fileExists('root-ca.crt') && !force) {
    console.log(`PKI already initialised at ${path.relative(ROOT, PKI_DIR) || PKI_DIR}`);
    console.log('Re-run with --force to regenerate (invalidates every issued certificate).');
    return;
  }
  if (force) fs.rmSync(PKI_DIR, { recursive: true, force: true });
  fs.mkdirSync(PKI_DIR, { recursive: true, mode: 0o700 });

  console.log('Generating root CA…');
  makeCa('Zero Trust Demo Root CA', null, 'root-ca');
  console.log('Generating device CA…');
  makeCa(
    'Zero Trust Device Issuing CA',
    { cert: path.join(PKI_DIR, 'root-ca.crt'), key: path.join(PKI_DIR, 'root-ca.key') },
    'device-ca',
  );
  console.log('Generating server CA…');
  makeCa(
    'Zero Trust Server Issuing CA',
    { cert: path.join(PKI_DIR, 'root-ca.crt'), key: path.join(PKI_DIR, 'root-ca.key') },
    'server-ca',
  );
  console.log('Generating proxy TLS certificate…');
  makeServerCert();

  console.log('Issuing device certificates…');
  const devices = DEMO_DEVICES.map((device) => {
    const entry = makeDeviceCert(device);
    console.log(`  ${entry.id}  serial=${entry.serial}  fp=${entry.fingerprint256.slice(0, 16)}…`);
    return entry;
  });
  fs.writeFileSync(
    path.join(PKI_DIR, 'devices.json'),
    `${JSON.stringify({ generatedAt: new Date().toISOString(), devices }, null, 2)}\n`,
    { mode: 0o644 },
  );
  fs.writeFileSync(
    path.join(PKI_DIR, 'README.txt'),
    [
      'DEMO PKI — generated by scripts/pki.ts',
      '',
      'The root, issuing CA and device private keys are on disk unencrypted.',
      'This is a lab setup: in production the issuing keys belong in an HSM and',
      'device keys never leave the device (TPM / Secure Enclave).',
      '',
      'Device bundles (import into browser/OS keychain, password "changeit"):',
      ...devices.map((device) => `  pki/devices/${device.id}/${device.id}.p12  — ${device.displayName}`),
      '',
      'CAs (trust anchors):',
      '  pki/root-ca.crt',
      '  pki/device-ca.crt',
      '  pki/server-ca.crt',
      '',
    ].join('\n'),
    { mode: 0o644 },
  );

  console.log(`\nPKI written to ${path.relative(ROOT, PKI_DIR) || PKI_DIR}`);
  console.log('Next: npm run demo');
}

function show(): void {
  const manifestPath = path.join(PKI_DIR, 'devices.json');
  if (!fs.existsSync(manifestPath)) {
    console.log('No devices.json — run `npm run pki:init` first.');
    process.exitCode = 1;
    return;
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
    generatedAt: string;
    devices: DeviceManifestEntry[];
  };
  console.log(`PKI: ${path.relative(ROOT, PKI_DIR) || PKI_DIR} (generated ${manifest.generatedAt})\n`);
  for (const device of manifest.devices) {
    console.log(`${device.id}  ${device.displayName}`);
    console.log(`  owner=${device.ownerUsername ?? '-'}  group=${device.group}`);
    console.log(`  serial=${device.serial}  expires=${device.expiresAt}`);
    console.log(`  sha256=${device.fingerprint256}`);
    console.log(`  bundle=pki/devices/${device.id}/${device.id}.p12 (password: changeit)`);
  }
}

const command = process.argv[2] ?? 'init';
if (command === 'init') {
  init(process.argv.includes('--force'));
} else if (command === 'show') {
  show();
} else {
  console.error(`unknown command "${command}" — use "init" or "show"`);
  process.exitCode = 2;
}
