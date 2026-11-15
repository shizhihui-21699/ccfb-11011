import * as fs from 'fs';
import * as path from 'path';
import { CERTS_DIR, createCa, issueServerCert, issueDeviceCert } from '../src/ca';

/**
 * Bootstrap the demo PKI: a self-signed root CA, the proxy's server cert,
 * and one client certificate per enrolled device. Device IDs are embedded
 * in the cert CN and a SAN URI (urn:device:<id>).
 */
const devices = ['laptop-01', 'laptop-02'];

if (fs.existsSync(path.join(CERTS_DIR, 'ca.key.pem'))) {
  console.log('certs/ already exists — delete it to re-generate');
  process.exit(0);
}

const ca = createCa();
issueServerCert(ca);
for (const d of devices) issueDeviceCert(ca, d);

console.log(`CA + server cert + device certs written to ${CERTS_DIR}`);
for (const d of devices) console.log(`  device: ${d}`);
