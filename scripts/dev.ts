import { spawn, type ChildProcess } from 'node:child_process';
import { SEED_DEVICES } from './setup.ts';

/**
 * Developer convenience: run the posture service, the mock upstreams, one
 * simulated device agent per seed device, and the access proxy together, with
 * prefixed logs. Ctrl-C stops all of them.
 *
 * The agents matter: posture reports go stale within a minute, and a stale
 * report is a blocking condition by design.
 */
const children: ChildProcess[] = [];

function start(name: string, script: string, env: NodeJS.ProcessEnv = {}): void {
  const child = spawn(process.execPath, [script], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  const prefix = `[${name}] `;
  const pipe = (stream: NodeJS.ReadableStream | null, out: NodeJS.WriteStream) => {
    stream?.on('data', (chunk: Buffer) => {
      for (const line of chunk.toString().split('\n')) {
        if (line.trim()) out.write(`${prefix}${line}\n`);
      }
    });
  };
  pipe(child.stdout, process.stdout);
  pipe(child.stderr, process.stderr);
  child.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      console.error(`${prefix}exited with code ${code}`);
      shutdown(code ?? 1);
    }
  });
  console.log(`${prefix}started (pid ${child.pid})`);
}

function shutdown(code = 0): void {
  for (const child of children) child.kill('SIGTERM');
  setTimeout(() => process.exit(code), 500).unref();
}

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

start('posture', 'src/postureServiceMain.ts');
start('upstream', 'scripts/mockUpstream.ts');

setTimeout(() => {
  for (const device of SEED_DEVICES) {
    // Carol's device starts in its broken state so the denial path is visible.
    const broken = device.id === 'dev-carol-linux';
    start(`agent:${device.id.replace('dev-', '')}`, 'scripts/device-agent.ts', {
      ZTA_AGENT_DEVICE: device.id,
      ...(broken ? { ZTA_AGENT_EDR: 'off' } : {}),
    });
  }
  start('proxy', 'src/main.ts');
}, 600);
