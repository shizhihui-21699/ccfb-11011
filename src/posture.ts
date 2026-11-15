import express from 'express';
import { DevicePosture } from './policy';
import { AuditLog } from './audit';

export const POSTURE_PORT = 8300;
export const POSTURE_BASE = `http://127.0.0.1:${POSTURE_PORT}`;
/** Shared secret between device agents / admin tooling and the posture service. */
export const POSTURE_TOKEN = 'posture-demo-token';

/**
 * Mock device-posture service. Device agents POST /report with their current
 * posture; the proxy and admin UI read it back over HTTP. Stands in for a
 * real MDM/EDR fleet API.
 */
export function startPostureService(audit: AuditLog): void {
  const app = express();
  app.use(express.json());
  const store = new Map<string, DevicePosture>();

  app.use((req, res, next) => {
    if (req.path === '/health') return next();
    if (req.headers['x-posture-token'] !== POSTURE_TOKEN) {
      res.status(401).json({ error: 'bad token' });
      return;
    }
    next();
  });

  app.get('/health', (_req, res) => res.json({ ok: true }));

  app.post('/report', (req, res) => {
    const { deviceId, osVersion, diskEncrypted, edrOnline } = req.body ?? {};
    if (typeof deviceId !== 'string' || typeof osVersion !== 'string') {
      res.status(400).json({ error: 'deviceId and osVersion required' });
      return;
    }
    const posture: DevicePosture = {
      deviceId,
      osVersion,
      diskEncrypted: diskEncrypted === true,
      edrOnline: edrOnline === true,
      reportedAt: Date.now(),
    };
    store.set(deviceId, posture);
    audit.record({
      ts: new Date().toISOString(),
      kind: 'posture_report',
      outcome: 'info',
      deviceId,
      reason: `os=${osVersion} diskEncrypted=${posture.diskEncrypted} edrOnline=${posture.edrOnline}`,
    });
    res.json({ ok: true });
  });

  app.get('/posture/:deviceId', (req, res) => {
    const p = store.get(req.params.deviceId);
    if (!p) {
      res.status(404).json({ error: 'unknown device' });
      return;
    }
    res.json(p);
  });

  app.get('/devices', (_req, res) => {
    res.json([...store.values()].sort((a, b) => a.deviceId.localeCompare(b.deviceId)));
  });

  app.listen(POSTURE_PORT, '127.0.0.1', () => {
    console.log(`[posture] mock posture service on ${POSTURE_BASE}`);
  });
}

/** Client used by the proxy/admin to read posture back. */
export async function fetchPosture(deviceId: string): Promise<DevicePosture | null> {
  try {
    const r = await fetch(`${POSTURE_BASE}/posture/${encodeURIComponent(deviceId)}`, {
      headers: { 'x-posture-token': POSTURE_TOKEN },
    });
    if (!r.ok) return null;
    return (await r.json()) as DevicePosture;
  } catch {
    return null;
  }
}

export async function fetchDevices(): Promise<DevicePosture[]> {
  try {
    const r = await fetch(`${POSTURE_BASE}/devices`, {
      headers: { 'x-posture-token': POSTURE_TOKEN },
    });
    if (!r.ok) return [];
    return (await r.json()) as DevicePosture[];
  } catch {
    return [];
  }
}
