/**
 * Simulated on-device posture agent.
 *
 * Reads the device's starting state from data/posture.json (written by setup),
 * then reports to the local posture service on an interval. Flags let an
 * operator break the device on purpose to watch the proxy react:
 *
 *   npm run agent -- --device dev-alice-macbook --edr off
 *   npm run agent -- --device dev-alice-macbook --disk plaintext
 *   npm run agent -- --device dev-alice-macbook --os 13.6
 *   npm run agent -- --device dev-alice-macbook --heartbeat-stale
 *
 * In a real deployment this process is the EDR/MDM shim: it collects facts
 * locally, signs them (here: a per-device bearer token), and posts them.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT_DIR } from '../src/config.ts';
import { createLogger, setLogLevel } from '../src/log.ts';
import { nowIso } from '../src/util.ts';
import { SEED_DEVICES } from './setup.ts';

const log = createLogger('device-agent');

interface Args {
  device: string;
  intervalSeconds: number;
  os?: string;
  edr: 'on' | 'off' | 'missing';
  disk: 'encrypted' | 'plaintext';
  heartbeatStale: boolean;
  once: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    device: process.env.ZTA_AGENT_DEVICE ?? SEED_DEVICES[0].id,
    intervalSeconds: Number.parseInt(process.env.ZTA_AGENT_INTERVAL ?? '10', 10) || 10,
    os: process.env.ZTA_AGENT_OS,
    edr: (process.env.ZTA_AGENT_EDR as Args['edr']) ?? 'on',
    disk: (process.env.ZTA_AGENT_DISK as Args['disk']) ?? 'encrypted',
    heartbeatStale: process.env.ZTA_AGENT_HEARTBEAT_STALE === '1',
    once: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = argv[i + 1];
    switch (flag) {
      case '--device':
        args.device = String(value);
        i += 1;
        break;
      case '--interval':
        args.intervalSeconds = Math.max(1, Number.parseInt(String(value), 10) || 10);
        i += 1;
        break;
      case '--os':
        args.os = String(value);
        i += 1;
        break;
      case '--edr':
        if (value !== 'on' && value !== 'off' && value !== 'missing') {
          throw new Error('--edr must be on, off or missing');
        }
        args.edr = value;
        i += 1;
        break;
      case '--disk':
        if (value !== 'encrypted' && value !== 'plaintext') {
          throw new Error('--disk must be encrypted or plaintext');
        }
        args.disk = value;
        i += 1;
        break;
      case '--heartbeat-stale':
        args.heartbeatStale = true;
        break;
      case '--once':
        args.once = true;
        break;
      case '--help':
      case '-h':
        console.log(
          'usage: npm run agent -- [--device <id>] [--interval <s>] [--os <version>] [--edr on|off|missing] [--disk encrypted|plaintext] [--heartbeat-stale] [--once]',
        );
        process.exit(0);
        break;
      default:
        throw new Error(`unknown flag ${flag}`);
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
setLogLevel(process.env.ZTA_LOG_LEVEL === 'debug' ? 'debug' : 'info');

const seed = SEED_DEVICES.find((device) => device.id === args.device);
if (!seed) {
  console.error(`unknown device ${args.device}. Known: ${SEED_DEVICES.map((d) => d.id).join(', ')}`);
  process.exit(2);
}
const deviceSeed = seed;

const tokens = JSON.parse(readFileSync(join(ROOT_DIR, 'data', 'agent-tokens.json'), 'utf8')) as {
  tokens: Record<string, string>;
};
const token = tokens.tokens[args.device];
if (!token) throw new Error(`no agent token for ${args.device}; run "npm run setup -- --force"`);

const postureUrl = (process.env.ZTA_POSTURE_URL ?? 'http://127.0.0.1:8450').replace(/\/+$/, '');

function buildReport(): Record<string, unknown> {
  const now = Date.now();
  return {
    deviceId: args.device,
    platform: deviceSeed.platform,
    osVersion: args.os ?? deviceSeed.posture.osVersion,
    diskEncrypted: args.disk === 'encrypted',
    edrInstalled: args.edr !== 'missing',
    edrRunning: args.edr === 'on',
    edrLastHeartbeatAt: new Date(args.heartbeatStale ? now - 10 * 60_000 : now).toISOString(),
    agentVersion: '1.4.2-sim',
    reportedAt: new Date(now).toISOString(),
    source: 'simulator',
  };
}

async function report(): Promise<void> {
  const response = await fetch(`${postureUrl}/v1/report`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-token': token },
    body: JSON.stringify(buildReport()),
  }).catch((error: Error) => {
    throw new Error(`posture service unreachable at ${postureUrl}: ${error.message}`);
  });
  if (!response.ok) throw new Error(`report rejected: ${response.status} ${await response.text()}`);
  const body = (await response.json()) as { revision: number };
  log.info('reported', {
    device: args.device,
    revision: body.revision,
    edr: args.edr,
    disk: args.disk,
    at: nowIso(),
  });
}

log.info('device agent starting', {
  device: args.device,
  postureUrl,
  intervalSeconds: args.intervalSeconds,
  edr: args.edr,
  disk: args.disk,
});

if (args.once) {
  await report();
  process.exit(0);
}

await report().catch((error: Error) => {
  log.error(error.message);
  process.exitCode = 1;
});

const timer = setInterval(() => {
  report().catch((error: Error) => log.error(error.message));
}, args.intervalSeconds * 1000);

const stop = () => {
  clearInterval(timer);
  log.info('device agent stopped');
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
