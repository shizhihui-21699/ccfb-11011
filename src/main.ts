#!/usr/bin/env -S node
/**
 * Process entry point. Boots the posture service (unless an external one is
 * configured), the runtime, and the TLS listener; handles graceful shutdown.
 *
 * Everything the demo needs is started by `scripts/demo.ts`; this file is what
 * you would run in a real deployment with an external posture service:
 *
 *   ZT_POSTURE_URL=https://posture.internal node src/main.ts
 */
import { loadConfig } from './config.ts';
import { assertValidApps } from './config.ts';
import { createRuntime, seedPostureFromManifest } from './core/runtime.ts';
import { startServer } from './http/server.ts';
import { PostureService, defaultManifestPath } from './services/posture-service.ts';

async function main(): Promise<void> {
  const config = loadConfig();
  assertValidApps(config.apps);
  const runtime = await createRuntime({ config });
  seedPostureFromManifest(runtime.posture, config);

  // Start a local posture service only when no external one is configured.
  let postureService: PostureService | null = null;
  if (process.env.ZT_POSTURE_URL === undefined) {
    postureService = new PostureService({
      host: config.postureService.host,
      port: config.postureService.port,
      manifestPath: defaultManifestPath(config.pkiDir),
      logger: runtime.logger,
    });
    const boundPort = await postureService.start();
    runtime.logger('posture.service_started', { url: `http://${config.postureService.host}:${boundPort}` });
  }

  await runtime.startBackground();
  const server = await startServer({ runtime });
  runtime.logger('proxy.listening', {
    url: server.url,
    apps: config.apps.map((app) => app.id),
    revalidateMs: config.thresholds.revalidateIntervalMs,
    revokeWithinMs: config.thresholds.revokeWithinMs,
  });

  const shutdown = async (signal: string): Promise<void> => {
    runtime.logger('proxy.shutdown', { signal });
    await server.close();
    await postureService?.stop();
    await runtime.shutdown();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`);
  process.exit(1);
});
