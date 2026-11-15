export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const levels: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

function configuredLevel(): LogLevel {
  const raw = (process.env.ZTA_LOG_LEVEL ?? 'info').toLowerCase();
  return raw in levels ? (raw as LogLevel) : 'info';
}

let minLevel = configuredLevel();

export function setLogLevel(level: LogLevel): void {
  minLevel = level;
}

function emit(level: LogLevel, component: string, message: string, fields?: Record<string, unknown>): void {
  if (levels[level] < levels[minLevel]) return;
  const record: Record<string, unknown> = {
    ts: new Date().toISOString(),
    level,
    component,
    message,
  };
  if (fields) Object.assign(record, fields);
  const line = JSON.stringify(record);
  if (level === 'error' || level === 'warn') process.stderr.write(`${line}\n`);
  else process.stdout.write(`${line}\n`);
}

export interface Logger {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
}

export function createLogger(component: string): Logger {
  return {
    debug: (message, fields) => emit('debug', component, message, fields),
    info: (message, fields) => emit('info', component, message, fields),
    warn: (message, fields) => emit('warn', component, message, fields),
    error: (message, fields) => emit('error', component, message, fields),
  };
}
