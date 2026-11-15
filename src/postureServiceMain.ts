import { createPostureService } from './postureService.ts';
import { createLogger } from './log.ts';

const log = createLogger('posture-service');

const service = createPostureService();
const port = await service.listen();
log.info('posture service listening', {
  url: `http://${process.env.ZTA_POSTURE_HOST ?? '127.0.0.1'}:${port}`,
});

const shutdown = (signal: string) => {
  log.info('shutting down', { signal });
  void service.close().then(() => process.exit(0));
  setTimeout(() => process.exit(0), 2_000).unref();
};
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
