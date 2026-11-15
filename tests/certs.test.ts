import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { test } from 'node:test';
import crypto from 'node:crypto';
import {
  loadTrustMaterial,
  verifyClientCertificate,
  parseSubjectAltNames,
} from '../src/pki/trust.ts';
import { buildTestPki } from './helpers/pki.ts';

const read = (path: string): Buffer => fs.readFileSync(path);
const openssl = (args: string[]): void => {
  execFileSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
};

function presented(deviceCertPath: string): crypto.X509Certificate {
  return new crypto.X509Certificate(read(deviceCertPath));
}

test('accepts a device certificate issued by the device CA', () => {
  const pki = buildTestPki([{ id: 'dev-1', owner: 'alice', group: 'engineering' }]);
  const trust = loadTrustMaterial(pki.dir);
  const check = verifyClientCertificate(presented(pki.devices[0]!.certPath), trust);
  assert.equal(check.ok, true);
  assert.equal(check.identity?.deviceId, 'dev-1');
  assert.equal(check.identity?.userHint, 'alice');
  assert.equal(check.failure, null);
});

test('rejects a certificate signed by a different CA', () => {
  const goodPki = buildTestPki([{ id: 'dev-1', owner: 'alice', group: 'engineering' }]);
  const otherPki = buildTestPki([{ id: 'dev-2', owner: 'mallory', group: 'engineering' }]);
  const trust = loadTrustMaterial(goodPki.dir);
  const check = verifyClientCertificate(presented(otherPki.devices[0]!.certPath), trust);
  assert.equal(check.ok, false);
  // Either detection is acceptable: issuer binding and signature verification
  // are both independent checks, and which one fires first is an detail of
  // the certificate layout. Both mean "not signed by our device CA".
  assert.ok(['not_device_ca_issued', 'signature_invalid'].includes(check.failure ?? ''));
});

test('rejects an expired certificate', () => {
  const pki = buildTestPki([{ id: 'dev-1', owner: 'alice', group: 'engineering' }]);
  const trust = loadTrustMaterial(pki.dir);
  const cert = presented(pki.devices[0]!.certPath);
  const farFuture = new Date(cert.validToDate.getTime() + 86_400_000);
  const check = verifyClientCertificate(cert, trust, farFuture);
  assert.equal(check.ok, false);
  assert.equal(check.failure, 'expired');
});

test('rejects a certificate that is not yet valid', () => {
  const pki = buildTestPki([{ id: 'dev-1', owner: 'alice', group: 'engineering' }]);
  const trust = loadTrustMaterial(pki.dir);
  const cert = presented(pki.devices[0]!.certPath);
  const past = new Date(cert.validFromDate.getTime() - 86_400_000);
  const check = verifyClientCertificate(cert, trust, past);
  assert.equal(check.ok, false);
  assert.equal(check.failure, 'not_yet_valid');
});

function signRaw(dir: string, name: string, subjectAltName: string | null): string {
  const key = `${dir}/${name}.key`;
  const csr = `${dir}/${name}.csr`;
  const crt = `${dir}/${name}.crt`;
  const ext = `${dir}/${name}.ext`;
  openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key]);
  openssl(['req', '-new', '-key', key, '-subj', `/CN=${name}`, '-out', csr]);
  fs.writeFileSync(
    ext,
    [
      'basicConstraints=critical,CA:FALSE',
      'keyUsage=critical,digitalSignature',
      'extendedKeyUsage=clientAuth',
      ...(subjectAltName === null ? [] : [`subjectAltName=${subjectAltName}`]),
      '',
    ].join('\n'),
  );
  openssl([
    'x509', '-req', '-in', csr, '-CA', `${dir}/device-ca.crt`, '-CAkey', `${dir}/device-ca.key`,
    '-set_serial', '0x999', '-days', '90', '-sha256', '-extfile', ext, '-out', crt,
  ]);
  return crt;
}

test('rejects a certificate without the device SAN URI', () => {
  const pki = buildTestPki([{ id: 'dev-1', owner: 'alice', group: 'engineering' }]);
  const trust = loadTrustMaterial(pki.dir);
  const crt = signRaw(pki.dir, 'no-san', null);
  const check = verifyClientCertificate(presented(crt), trust);
  assert.equal(check.ok, false);
  assert.equal(check.failure, 'missing_device_id');
});

test('rejects a device SAN with unsafe characters', () => {
  const pki = buildTestPki([{ id: 'dev-1', owner: 'alice', group: 'engineering' }]);
  const trust = loadTrustMaterial(pki.dir);
  const crt = signRaw(pki.dir, 'bad-id', 'URI:urn:zt:device:bad id');
  const check = verifyClientCertificate(presented(crt), trust);
  assert.equal(check.ok, false);
  assert.equal(check.failure, 'malformed_device_id');
});

test('a server certificate is not accepted as a client certificate', () => {
  const pki = buildTestPki([{ id: 'dev-1', owner: 'alice', group: 'engineering' }]);
  const trust = loadTrustMaterial(pki.dir);
  const proxy = new crypto.X509Certificate(read(`${pki.dir}/proxy.crt`));
  const check = verifyClientCertificate(proxy, trust);
  assert.equal(check.ok, false);
  // Either detection is acceptable: issuer binding and signature verification
  // are both independent checks, and which one fires first is an detail of
  // the certificate layout. Both mean "not signed by our device CA".
  assert.ok(['not_device_ca_issued', 'signature_invalid'].includes(check.failure ?? ''));
});

test('certificate issued by the device CA but used for server auth is rejected', () => {
  const pki = buildTestPki([{ id: 'dev-1', owner: 'alice', group: 'engineering' }]);
  const trust = loadTrustMaterial(pki.dir);
  const dir = pki.dir;
  const key = `${dir}/serverauth.key`;
  const csr = `${dir}/serverauth.csr`;
  const crt = `${dir}/serverauth.crt`;
  const ext = `${dir}/serverauth.ext`;
  openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key]);
  openssl(['req', '-new', '-key', key, '-subj', '/CN=sneaky', '-out', csr]);
  fs.writeFileSync(
    ext,
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=URI:urn:zt:device:dev-1\n',
  );
  openssl([
    'x509', '-req', '-in', csr, '-CA', `${dir}/device-ca.crt`, '-CAkey', `${dir}/device-ca.key`,
    '-set_serial', '0x997', '-days', '90', '-sha256', '-extfile', ext, '-out', crt,
  ]);
  const check = verifyClientCertificate(presented(crt), trust);
  assert.equal(check.ok, false);
  assert.equal(check.failure, 'wrong_key_usage');
});

test('parseSubjectAltNames keeps only URI entries', () => {
  assert.deepEqual(
    parseSubjectAltNames('URI:urn:zt:device:dev-1, URI:urn:zt:user:alice, DNS:example.com'),
    ['urn:zt:device:dev-1', 'urn:zt:user:alice'],
  );
  assert.deepEqual(parseSubjectAltNames(''), []);
  assert.deepEqual(parseSubjectAltNames('DNS:only-a-name'), []);
});
