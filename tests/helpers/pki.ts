/**
 * Test helpers: a self-contained environment with its own temp PKI, database
 * and posture service. Certificate generation shells out to OpenSSL the same
 * way `scripts/pki.ts` does, so tests exercise real X.509 material.
 */
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface TestDevice {
  id: string;
  ownerUsername: string | null;
  group: string;
  certPath: string;
  keyPath: string;
  fingerprint256: string;
  serial: string;
}

export interface TestPki {
  dir: string;
  devices: TestDevice[];
  caBundlePath: string;
}

const ROOT = path.resolve(import.meta.dirname, '..');

export function makeTempDir(prefix = 'zt-test-'): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function openssl(args: string[]): void {
  execFileSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
}

/** Builds a root CA plus a device issuing CA and client certs for `devices`. */
export function buildTestPki(
  devices: { id: string; owner: string | null; group: string }[],
): TestPki {
  const dir = makeTempDir('zt-pki-');
  const ca = path.join(dir, 'root-ca');
  openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', `${ca}.key`]);
  openssl([
    'req', '-x509', '-new', '-key', `${ca}.key`, '-sha256', '-days', '3650',
    '-subj', '/CN=ZT Test Root CA',
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    '-out', `${ca}.crt`,
  ]);
  const deviceCa = path.join(dir, 'device-ca');
  openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', `${deviceCa}.key`]);
  openssl(['req', '-new', '-key', `${deviceCa}.key`, '-subj', '/CN=ZT Test Device CA', '-out', `${deviceCa}.csr`]);
  const deviceExt = path.join(dir, 'device-ca.ext');
  fs.writeFileSync(deviceExt, 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n');
  openssl([
    'x509', '-req', '-in', `${deviceCa}.csr`, '-CA', `${ca}.crt`, '-CAkey', `${ca}.key`,
    '-set_serial', '0x1000', '-days', '1825', '-sha256', '-extfile', deviceExt, '-out', `${deviceCa}.crt`,
  ]);

  const serverCa = path.join(dir, 'server-ca');
  openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', `${serverCa}.key`]);
  openssl(['req', '-new', '-key', `${serverCa}.key`, '-subj', '/CN=ZT Test Server CA', '-out', `${serverCa}.csr`]);
  const serverCaExt = path.join(dir, 'server-ca.ext');
  fs.writeFileSync(serverCaExt, 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n');
  openssl([
    'x509', '-req', '-in', `${serverCa}.csr`, '-CA', `${ca}.crt`, '-CAkey', `${ca}.key`,
    '-set_serial', '0x2000', '-days', '1825', '-sha256', '-extfile', serverCaExt, '-out', `${serverCa}.crt`,
  ]);

  const proxyExt = path.join(dir, 'proxy.ext');
  fs.writeFileSync(
    proxyExt,
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n',
  );
  openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', path.join(dir, 'proxy.key')]);
  openssl(['req', '-new', '-key', path.join(dir, 'proxy.key'), '-subj', '/CN=localhost', '-out', path.join(dir, 'proxy.csr')]);
  openssl([
    'x509', '-req', '-in', path.join(dir, 'proxy.csr'), '-CA', `${serverCa}.crt`, '-CAkey', `${serverCa}.key`,
    '-set_serial', '0x2001', '-days', '397', '-sha256', '-extfile', proxyExt, '-out', path.join(dir, 'proxy.crt'),
  ]);

  const caBundle = path.join(dir, 'ca-bundle.pem');
  fs.writeFileSync(caBundle, `${fs.readFileSync(`${ca}.crt`, 'utf8')}\n${fs.readFileSync(`${deviceCa}.crt`, 'utf8')}`);

  const built: TestDevice[] = devices.map((device, index) => {
    const deviceDir = path.join(dir, 'devices', device.id);
    fs.mkdirSync(deviceDir, { recursive: true });
    const key = path.join(deviceDir, `${device.id}.key`);
    const csr = path.join(deviceDir, `${device.id}.csr`);
    const cert = path.join(deviceDir, `${device.id}.crt`);
    const ext = path.join(deviceDir, `${device.id}.ext`);
    openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key]);
    openssl(['req', '-new', '-key', key, '-subj', `/CN=${device.id}`, '-out', csr]);
    fs.writeFileSync(
      ext,
      `basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:urn:zt:device:${device.id},URI:urn:zt:user:${device.owner ?? 'unassigned'}
`,
    );
    const serial = (0x3000 + index).toString(16);
    openssl([
      'x509', '-req', '-in', csr, '-CA', `${deviceCa}.crt`, '-CAkey', `${deviceCa}.key`,
      '-set_serial', `0x${serial}`, '-days', '90', '-sha256', '-extfile', ext, '-out', cert,
    ]);
    const parsed = new crypto.X509Certificate(fs.readFileSync(cert));
    return {
      id: device.id,
      ownerUsername: device.owner,
      group: device.group,
      certPath: cert,
      keyPath: key,
      fingerprint256: parsed.fingerprint256.replaceAll(':', '').toLowerCase(),
      serial,
    };
  });

  return { dir, devices: built, caBundlePath: caBundle };
}

export function writeTestConfig(
  pki: TestPki,
  overrides: Record<string, unknown> = {},
  policy: unknown = {
    version: 1,
    rules: [
      { id: 'wiki-all', effect: 'allow', apps: ['wiki'], roles: ['employee', 'admin'], maxPostureAgeSeconds: 120 },
      {
        id: 'payroll-finance',
        effect: 'allow',
        apps: ['payroll'],
        groups: ['finance'],
        requireDiskEncrypted: true,
        requireEdrOnline: true,
      },
    ],
  },
): { configPath: string; root: string } {
  const root = makeTempDir('zt-root-');
  const configDir = path.join(root, 'config');
  fs.mkdirSync(configDir, { recursive: true });
  const config = {
    host: '127.0.0.1',
    port: 0,
    publicOrigin: 'https://127.0.0.1',
    pkiDir: pki.dir,
    dbPath: path.join(root, '.zt', 'test.db'),
    sessionSecret: 'test-session-secret-value-0123456789',
    sessionTtlSeconds: 3600,
    grantTtlSeconds: 3600,
    thresholds: {
      postureMaxAgeSeconds: 180,
      minOsVersion: { macos: '14.0.0', windows: '10.0.19045', linux: '5.15.0' },
      revalidateIntervalMs: 250,
      revokeWithinMs: 60_000,
    },
    postureService: { host: '127.0.0.1', port: 0 },
    apps: [
      { id: 'wiki', name: 'Wiki', upstream: 'http://127.0.0.1:1' },
      { id: 'payroll', name: 'Payroll', upstream: 'http://127.0.0.1:1' },
    ],
    seedUsers: [
      { id: 'usr_admin', username: 'admin', displayName: 'Admin', password: 'admin-password', roles: ['admin'], group: 'engineering' },
      { id: 'usr_emp', username: 'emp', displayName: 'Employee', password: 'emp-password', roles: ['employee'], group: 'finance' },
    ],
    ...overrides,
  };
  const configPath = path.join(configDir, 'zero-trust.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  fs.writeFileSync(path.join(configDir, 'policy.json'), JSON.stringify(policy, null, 2));
  return { configPath, root };
}

export const REPO_ROOT = ROOT;
