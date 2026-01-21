/**
 * Rate limiter for protecting against DoS attacks.
 * Per SPECS 4.1.3: Stealth nodes MUST rate-limit unauthenticated handshakes.
 *
 * Uses a sliding window algorithm with configurable limits.
 */

export interface RateLimiterConfig {
  /** Maximum number of requests allowed within the window */
  maxRequests: number;
  /** Window size in milliseconds */
  windowMs: number;
  /** Optional cleanup interval in milliseconds (default: windowMs * 2) */
  cleanupIntervalMs?: number;
}

interface RequestRecord {
  timestamps: number[];
}

/**
 * Rate limiter using sliding window algorithm.
 * Thread-safe for single-threaded Node.js event loop.
 */
export class RateLimiter {
  private config: Required<RateLimiterConfig>;
  private requests: Map<string, RequestRecord> = new Map();
  private cleanupTimer: NodeJS.Timeout | null = null;

  constructor(config: RateLimiterConfig) {
    this.config = {
      ...config,
      cleanupIntervalMs: config.cleanupIntervalMs ?? config.windowMs * 2,
    };

    // Start periodic cleanup
    this.startCleanup();
  }

  /**
   * Check if a request from the given key should be allowed.
   * @param key Identifier for the requester (e.g., IP address)
   * @returns true if request is allowed, false if rate limited
   */
  isAllowed(key: string): boolean {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;

    let record = this.requests.get(key);
    if (!record) {
      record = { timestamps: [] };
      this.requests.set(key, record);
    }

    // Remove timestamps outside the window
    record.timestamps = record.timestamps.filter(ts => ts > windowStart);

    // Check if within limit
    if (record.timestamps.length >= this.config.maxRequests) {
      return false;
    }

    // Record this request
    record.timestamps.push(now);
    return true;
  }

  /**
   * Record a request and return whether it was allowed.
   * Alias for isAllowed() for clearer API.
   */
  recordRequest(key: string): boolean {
    return this.isAllowed(key);
  }

  /**
   * Get the number of requests in the current window for a key.
   */
  getRequestCount(key: string): number {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    const record = this.requests.get(key);

    if (!record) {
      return 0;
    }

    return record.timestamps.filter(ts => ts > windowStart).length;
  }

  /**
   * Get time until the next request would be allowed (in ms).
   * Returns 0 if a request is currently allowed.
   */
  getRetryAfter(key: string): number {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    const record = this.requests.get(key);

    if (!record) {
      return 0;
    }

    const validTimestamps = record.timestamps.filter(ts => ts > windowStart);
    if (validTimestamps.length < this.config.maxRequests) {
      return 0;
    }

    // Find the oldest timestamp that's still in the window
    const oldestInWindow = Math.min(...validTimestamps);
    return oldestInWindow + this.config.windowMs - now;
  }

  /**
   * Reset the rate limit for a specific key.
   */
  reset(key: string): void {
    this.requests.delete(key);
  }

  /**
   * Reset all rate limits.
   */
  resetAll(): void {
    this.requests.clear();
  }

  /**
   * Stop the rate limiter and clean up resources.
   */
  stop(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.requests.clear();
  }

  /**
   * Get current statistics.
   */
  getStats(): { totalKeys: number; totalRequests: number } {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    let totalRequests = 0;

    for (const record of this.requests.values()) {
      totalRequests += record.timestamps.filter(ts => ts > windowStart).length;
    }

    return {
      totalKeys: this.requests.size,
      totalRequests,
    };
  }

  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      const now = Date.now();
      const windowStart = now - this.config.windowMs;

      for (const [key, record] of this.requests.entries()) {
        record.timestamps = record.timestamps.filter(ts => ts > windowStart);
        if (record.timestamps.length === 0) {
          this.requests.delete(key);
        }
      }
    }, this.config.cleanupIntervalMs);

    // Don't prevent process exit
    this.cleanupTimer.unref();
  }
}

/**
 * Create a rate limiter with common presets.
 */
export const RateLimiterPresets = {
  /**
   * Strict rate limiting for Stealth mode per SPECS 4.1.3
   * 5 connection attempts per minute per IP
   */
  stealth: () => new RateLimiter({
    maxRequests: 5,
    windowMs: 60 * 1000, // 1 minute
  }),

  /**
   * Standard rate limiting for general use
   * 30 connection attempts per minute per IP
   */
  standard: () => new RateLimiter({
    maxRequests: 30,
    windowMs: 60 * 1000, // 1 minute
  }),

  /**
   * Relaxed rate limiting for trusted environments
   * 100 connection attempts per minute per IP
   */
  relaxed: () => new RateLimiter({
    maxRequests: 100,
    windowMs: 60 * 1000, // 1 minute
  }),
};
