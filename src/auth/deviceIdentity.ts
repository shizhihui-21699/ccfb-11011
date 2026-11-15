/**
 * Extract a device identity from a verified mTLS peer certificate.
 *
 * TLS has already proven possession of the private key and that the
 * certificate chains to our CA (rejectUnauthorized + ca). This module only
 * reads claims; registry checks happen in the auth layer.
 */
import type { PeerCertificate } from 'node:tls';
import type { DeviceIdentity } from '../types.ts';

export const DEVICE_ID_URI_PREFIX = 'urn:zta:device:';
export const DEVICE_ID_OID = '1.3.6.1.4.1.55555.1.1';

export class CertIdentityError extends Error {
  override name = 'CertIdentityError';
}

function collectSans(cert: PeerCertificate): string[] {
  const raw = (cert as unknown as { subjectaltname?: string }).subjectaltname;
  if (!raw) return [];
  return raw
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
}

/**
 * Reads the device id from a SAN URI (`urn:zta:device:<id>`), falling back to
 * the private extension OID. The CN is deliberately NOT used: CN is a display
 * name and is easy to collide.
 */
export function extractDeviceIdentity(cert: PeerCertificate | null | undefined): DeviceIdentity {
  if (!cert || !cert.raw) throw new CertIdentityError('client certificate is required');
  const sans = collectSans(cert);
  let deviceId: string | undefined;
  for (const san of sans) {
    const match = /^URI:urn:zta:device:(.+)$/i.exec(san);
    if (match) {
      deviceId = match[1].trim();
      break;
    }
  }
  if (!deviceId) {
    const extension = (cert as unknown as Record<string, unknown>)[DEVICE_ID_OID];
    if (typeof extension === 'string' && extension.trim()) deviceId = extension.trim();
  }
  if (!deviceId) {
    throw new CertIdentityError(`client certificate has no ${DEVICE_ID_URI_PREFIX}<id> SAN URI`);
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/.test(deviceId)) {
    throw new CertIdentityError(`device id "${deviceId}" contains unsupported characters`);
  }
  return {
    deviceId,
    fingerprint256: normalizeFingerprint(cert.fingerprint256),
    subject: Array.isArray(cert.subject?.CN) ? cert.subject.CN.join(', ') : (cert.subject?.CN ?? ''),
    serialNumber: cert.serialNumber ?? '',
    notAfter: cert.valid_to ?? '',
    sans,
  };
}

export function normalizeFingerprint(value: string | undefined | null): string {
  return (value ?? '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
}

export function fingerprintMatches(a: string, b: string): boolean {
  const left = normalizeFingerprint(a);
  const right = normalizeFingerprint(b);
  return left.length > 0 && left === right;
}
