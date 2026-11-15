/**
 * Small fixed-window rate limiter for login attempts.
 */
export class RateLimiter {
  private readonly failures = new Map<string, { count: number; windowStart: number; lockedUntil: number }>();
  private readonly maxFailures: number;
  private readonly windowMs: number;
  private readonly lockoutMs: number;

  constructor(options: { maxFailures: number; windowSeconds: number; lockoutSeconds: number }) {
    this.maxFailures = options.maxFailures;
    this.windowMs = options.windowSeconds * 1000;
    this.lockoutMs = options.lockoutSeconds * 1000;
  }

  check(key: string, now = Date.now()): { allowed: boolean; retryAfterSeconds?: number } {
    const entry = this.failures.get(key);
    if (!entry) return { allowed: true };
    if (entry.lockedUntil > now) {
      return { allowed: false, retryAfterSeconds: Math.ceil((entry.lockedUntil - now) / 1000) };
    }
    if (now - entry.windowStart > this.windowMs) {
      this.failures.delete(key);
      return { allowed: true };
    }
    return { allowed: true };
  }

  recordFailure(key: string, now = Date.now()): void {
    const entry = this.failures.get(key);
    if (!entry || now - entry.windowStart > this.windowMs) {
      this.failures.set(key, { count: 1, windowStart: now, lockedUntil: 0 });
      return;
    }
    entry.count += 1;
    if (entry.count >= this.maxFailures) {
      entry.lockedUntil = now + this.lockoutMs;
      entry.count = 0;
      entry.windowStart = now;
    }
  }

  recordSuccess(key: string): void {
    this.failures.delete(key);
  }

  /** Periodic cleanup so the map does not grow unbounded. */
  sweep(now = Date.now()): void {
    for (const [key, entry] of this.failures) {
      if (entry.lockedUntil < now && now - entry.windowStart > this.windowMs) this.failures.delete(key);
    }
  }
}
