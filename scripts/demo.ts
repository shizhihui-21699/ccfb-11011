#!/usr/bin/env -S node
/**
 * End-to-end demo orchestration:
 *
 *   mock upstream apps (9101–9103)
 *   simulated posture service (9200)
 *   the access proxy (https://127.0.0.1:8443)
 *
 * Prints exact `curl` commands that present each device certificate, so the
 * whole flow can be exercised without a browser. Ctrl-C stops everything.
 */
import path from 'node:path';
import { loadConfig } from '../src/config.ts';
import { createRuntime, seedPostureFromManifest } from '../src/core/runtime.ts';
import { startServer } from '../src/http/server.ts';
import { PostureService, defaultManifestPath } from '../src/services/posture-service.ts';
import { startMockApps, stopMockApps } from './mock-apps.ts';

const ROOT = path.resolve(import.meta.dirname, '..');

async function main(): Promise<void> {
  const config = loadConfig(process.env, ROOT);
  const runtime = await createRuntime({ config });
  const postureService = new PostureService({
    host: config.postureService.host,
    port: config.postureService.port,
    manifestPath: defaultManifestPath(config.pkiDir),
    logger: runtime.logger,
  });
  const posturePort = await postureService.start();
  await startMockApps();
  seedPostureFromManifest(runtime.posture, config);
  await runtime.startBackground();
  const server = await startServer({ runtime });

  const deviceDir = (id: string): string => path.join(config.pkiDir, 'devices', id, `${id}.crt`);
  const keyDir = (id: string): string => path.join(config.pkiDir, 'devices', id, `${id}.key`);
  const rel = (value: string): string => path.relative(ROOT, value);

  const line = '─'.repeat(78);
  console.log(`\n${line}`);
  console.log('  Zero-trust access proxy — demo running');
  console.log(line);
  console.log(`  Proxy            ${server.url}`);
  console.log(`  Posture service  http://${config.postureService.host}:${posturePort}`);
  console.log(`  Mock apps        http://127.0.0.1:9101 (wiki), :9102 (payroll), :9103 (ops-console)`);
  console.log(`  Re-evaluation    every ${config.thresholds.revalidateIntervalMs}ms, SLA ${config.thresholds.revokeWithinMs / 1000}s`);
  console.log('');
  console.log('  Browser: import the .p12 bundle (password "changeit") and open the proxy URL.');
  console.log(`    ALICE (admin)     ${rel(path.join(config.pkiDir, 'devices', 'dev-alice-mbp', 'dev-alice-mbp.p12'))}`);
  console.log(`    BOB   (finance)   ${rel(path.join(config.pkiDir, 'devices', 'dev-bob-win', 'dev-bob-win.p12'))}`);
  console.log(`    CAROL (stale)     ${rel(path.join(config.pkiDir, 'devices', 'dev-carol-mbp', 'dev-carol-mbp.p12'))}`);
  console.log('');
  console.log('  curl (ALICE):');
  console.log(`    curl -sk --cert ${rel(deviceDir('dev-alice-mbp'))} --key ${rel(keyDir('dev-alice-mbp'))} \\`);
  console.log(`      -c /tmp/alice.jar https://127.0.0.1:${server.port}/login \\`);
  console.log(`      -d 'username=alice&password=alice-demo-password&nonce=...'`);
  console.log('');
  console.log('  postures are visible at the posture service; flip a device to see revocation:');
  console.log(`    curl -s -X POST http://${config.postureService.host}:${posturePort}/v1/devices/dev-alice-mbp/state \\`);
  console.log(`      -H 'content-type: application/json' -d '{"edr":"off"}'`);
  console.log(line + '\n');

  const shutdown = async (signal: string): Promise<void> => {
    console.log(`\n[${signal}] shutting down`);
    await server.close();
    await postureService.stop();
    await stopMockApps();
    await runtime.shutdown();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  const report = runtime.revalidator;
  setInterval(() => {
    const last = report.getLastReport();
    if (last === null) return;
    if (last.revokedGrants > 0 || last.revokedSessions > 0) {
      console.log(
        `[revalidate:${last.trigger}] considered=${last.considered} revokedGrants=${last.revokedGrants} revokedSessions=${last.revokedSessions} in ${last.durationMs}ms`,
      );
    }
  }, 1000).unref();
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? (error.stack ?? error.message) : error);
  process.exit(1);
});
