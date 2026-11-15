/**
 * Mock upstream applications used by the demo. Not part of the security
 * boundary — it only echoes what the proxy asserted about the caller.
 *
 * The checked-in policy points three apps at ports 8460 (wiki), 8461 (finance)
 * and 8462 (ops); all three are started so every policy branch is reachable.
 */
import { createServer, type Server } from 'node:http';
import { createLogger } from '../src/log.ts';

const log = createLogger('mock-upstream');

const TARGETS: { port: number; name: string }[] = [
  { port: 8460, name: 'wiki' },
  { port: 8461, name: 'finance' },
  { port: 8462, name: 'ops' },
];

const servers: Server[] = [];

function handlerFor(name: string, port: number) {
  return (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => {
    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (key.startsWith('x-zta-') || key === 'x-request-id' || key === 'x-forwarded-for') {
        headers[key] = Array.isArray(value) ? value.join(',') : (value ?? '');
      }
    }
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const payload = {
        upstream: `${name}@${port}`,
        method: req.method,
        path: req.url,
        contentType: req.headers['content-type'] ?? null,
        bodyBytes: body.length,
        body: body.length > 0 ? body.toString('utf8').slice(0, 2_000) : null,
        assertedIdentity: headers,
        note: 'These headers are set by the access proxy after policy evaluation.',
      };
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      res.end(`${JSON.stringify(payload, null, 2)}\n`);
    });
  };
}

for (const target of TARGETS) {
  const server = createServer(handlerFor(target.name, target.port));
  server.listen(target.port, '127.0.0.1', () => log.info('mock upstream listening', target));
  servers.push(server);
}

const stop = () => {
  for (const server of servers) server.close();
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
