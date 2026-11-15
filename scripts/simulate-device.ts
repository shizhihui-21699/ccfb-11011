import { POSTURE_BASE, POSTURE_TOKEN } from '../src/posture';

/**
 * Simulated device agent: posts a posture report for a device.
 *
 *   npx tsx scripts/simulate-device.ts <deviceId> [osVersion] [diskEncrypted] [edrOnline]
 *
 * Defaults produce a healthy device. Examples:
 *   npx tsx scripts/simulate-device.ts laptop-01 15.2 true true
 *   npx tsx scripts/simulate-device.ts laptop-01 15.2 true false   # EDR drops -> revocation
 */
const [deviceId, osVersion = '15.2', diskEncrypted = 'true', edrOnline = 'true'] =
  process.argv.slice(2);

if (!deviceId) {
  console.error('usage: simulate-device.ts <deviceId> [osVersion] [diskEncrypted] [edrOnline]');
  process.exit(1);
}

const body = {
  deviceId,
  osVersion,
  diskEncrypted: diskEncrypted === 'true',
  edrOnline: edrOnline === 'true',
};

async function main() {
  const r = await fetch(`${POSTURE_BASE}/report`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-posture-token': POSTURE_TOKEN },
    body: JSON.stringify(body),
  });
  console.log(r.status, await r.text());
}

void main();
