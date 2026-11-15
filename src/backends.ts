import express from 'express';

/**
 * Mock internal applications — the things the proxy protects.
 * In a real deployment these are the existing internal systems.
 */
export function startBackends(): void {
  const finance = express();
  finance.use((req, res) => {
    res.send(
      `<h1>Finance ERP</h1><p>Internal app reached through the zero-trust proxy.</p>` +
        `<p>user=${req.headers['x-ztna-user']} device=${req.headers['x-ztna-device']}</p>`,
    );
  });
  finance.listen(9001, '127.0.0.1', () => console.log('[backend] finance on :9001'));

  const wiki = express();
  wiki.use((req, res) => {
    res.send(
      `<h1>Engineering Wiki</h1><p>Internal app reached through the zero-trust proxy.</p>` +
        `<p>user=${req.headers['x-ztna-user']} device=${req.headers['x-ztna-device']}</p>`,
    );
  });
  wiki.listen(9002, '127.0.0.1', () => console.log('[backend] wiki on :9002'));
}
