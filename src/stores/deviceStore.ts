/**
 * Device registry: enrolled devices and their certificate bindings.
 *
 * A device is only usable while its certificate fingerprint matches the
 * registry record AND the record is active. Revocation therefore takes effect
 * on the next TLS connection even if the certificate itself is still valid.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { DeviceRecord, DeviceRegistryFile, DeviceStatus } from '../types.ts';
import { nowIso } from '../util.ts';

export class DeviceStoreError extends Error {
  override name = 'DeviceStoreError';
}

export class DeviceStore {
  private readonly filePath: string;
  private devices = new Map<string, DeviceRecord>();
  private loaded = false;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  load(): void {
    this.devices.clear();
    if (existsSync(this.filePath)) {
      const raw = JSON.parse(readFileSync(this.filePath, 'utf8')) as DeviceRegistryFile;
      if (raw.version !== 1 || !Array.isArray(raw.devices)) {
        throw new DeviceStoreError(`${this.filePath}: unsupported device registry format`);
      }
      for (const device of raw.devices) this.devices.set(device.id, { ...device });
    }
    this.loaded = true;
  }

  private ensureLoaded(): void {
    if (!this.loaded) this.load();
  }

  private persist(): void {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const payload: DeviceRegistryFile = { version: 1, devices: this.list() };
    const tmp = `${this.filePath}.tmp-${process.pid}`;
    writeFileSync(tmp, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    renameSync(tmp, this.filePath);
  }

  list(): DeviceRecord[] {
    this.ensureLoaded();
    return [...this.devices.values()].sort((a, b) => a.id.localeCompare(b.id));
  }

  get(deviceId: string): DeviceRecord | undefined {
    this.ensureLoaded();
    const device = this.devices.get(deviceId);
    return device ? { ...device } : undefined;
  }

  findByFingerprint(fingerprint256: string): DeviceRecord | undefined {
    this.ensureLoaded();
    const normalized = normalizeFingerprint(fingerprint256);
    for (const device of this.devices.values()) {
      if (normalizeFingerprint(device.certFingerprint256) === normalized) return { ...device };
    }
    return undefined;
  }

  countForUser(userId: string): number {
    this.ensureLoaded();
    let count = 0;
    for (const device of this.devices.values()) {
      if (device.assignedTo === userId && device.status === 'active') count += 1;
    }
    return count;
  }

  setStatus(deviceId: string, status: DeviceStatus, reason?: string): DeviceRecord {
    this.ensureLoaded();
    const device = this.devices.get(deviceId);
    if (!device) throw new DeviceStoreError(`unknown device ${deviceId}`);
    device.status = status;
    if (status === 'revoked') {
      device.revokedAt = nowIso();
      device.revokeReason = reason;
    } else {
      delete device.revokedAt;
      delete device.revokeReason;
    }
    this.devices.set(deviceId, device);
    this.persist();
    return { ...device };
  }

  upsert(device: DeviceRecord): DeviceRecord {
    this.ensureLoaded();
    this.devices.set(device.id, { ...device });
    this.persist();
    return { ...device };
  }
}

export function normalizeFingerprint(value: string): string {
  return value.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
}
