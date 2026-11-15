import * as forge from 'node-forge';
import * as fs from 'fs';
import * as path from 'path';

export const CERTS_DIR = path.join(__dirname, '..', 'certs');

function ensureDir() {
  fs.mkdirSync(CERTS_DIR, { recursive: true });
}

function writePem(name: string, pem: string) {
  fs.writeFileSync(path.join(CERTS_DIR, name), pem, { mode: 0o600 });
}

export interface CaMaterial {
  certPem: string;
  keyPem: string;
}

/** Create a self-signed root CA used to sign the proxy server cert and device client certs. */
export function createCa(): CaMaterial {
  ensureDir();
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
  const attrs = [{ name: 'commonName', value: 'ZTNA-Demo-Root-CA' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const material: CaMaterial = {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
  writePem('ca.crt.pem', material.certPem);
  writePem('ca.key.pem', material.keyPem);
  return material;
}

export function loadCa(): CaMaterial {
  return {
    certPem: fs.readFileSync(path.join(CERTS_DIR, 'ca.crt.pem'), 'utf8'),
    keyPem: fs.readFileSync(path.join(CERTS_DIR, 'ca.key.pem'), 'utf8'),
  };
}

function makeCert(opts: {
  commonName: string;
  serial: string;
  isServer: boolean;
  ca: CaMaterial;
  sanUris?: string[];
  dnsNames?: string[];
}): { certPem: string; keyPem: string } {
  const caCert = forge.pki.certificateFromPem(opts.ca.certPem);
  const caKey = forge.pki.privateKeyFromPem(opts.ca.keyPem);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = opts.serial;
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 3);
  cert.setSubject([{ name: 'commonName', value: opts.commonName }]);
  cert.setIssuer(caCert.subject.attributes);
  const altNames: Array<{ type: number; value: string }> = [];
  for (const d of opts.dnsNames ?? []) altNames.push({ type: 2, value: d });
  for (const u of opts.sanUris ?? []) altNames.push({ type: 6, value: u });
  const extensions: object[] = [
    { name: 'basicConstraints', cA: false, critical: true },
    opts.isServer
      ? { name: 'extKeyUsage', serverAuth: true }
      : { name: 'extKeyUsage', clientAuth: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
  ];
  if (altNames.length) extensions.push({ name: 'subjectAltName', altNames });
  cert.setExtensions(extensions as never[]);
  cert.sign(caKey, forge.md.sha256.create());
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

let serialCounter = 0x1000;
function nextSerial(): string {
  return (serialCounter++).toString(16).toUpperCase();
}

/** Issue the proxy's TLS server certificate (CN=localhost). */
export function issueServerCert(ca: CaMaterial): void {
  const { certPem, keyPem } = makeCert({
    commonName: 'localhost',
    serial: nextSerial(),
    isServer: true,
    ca,
    dnsNames: ['localhost'],
  });
  writePem('server.crt.pem', certPem);
  writePem('server.key.pem', keyPem);
}

/**
 * Issue a device client certificate. The device ID is carried in the CN
 * and in a SAN URI of the form `urn:device:<deviceId>` so the proxy can
 * bind TLS identity to posture records.
 */
export function issueDeviceCert(ca: CaMaterial, deviceId: string): void {
  const { certPem, keyPem } = makeCert({
    commonName: deviceId,
    serial: nextSerial(),
    isServer: false,
    ca,
    sanUris: [`urn:device:${deviceId}`],
  });
  writePem(`device-${deviceId}.crt.pem`, certPem);
  writePem(`device-${deviceId}.key.pem`, keyPem);
}

/** Extract the device ID from a verified peer certificate (CN, fallback SAN URI). */
export function deviceIdFromPeerCert(cert: {
  subject?: { CN?: string | string[] };
  subjectaltname?: string;
}): string | null {
  const cn = cert.subject?.CN;
  if (typeof cn === 'string' && cn) return cn;
  if (Array.isArray(cn) && typeof cn[0] === 'string') return cn[0];
  const san = cert.subjectaltname;
  if (san) {
    const m = san.match(/URI:urn:device:([A-Za-z0-9._-]+)/);
    if (m) return m[1];
  }
  return null;
}
