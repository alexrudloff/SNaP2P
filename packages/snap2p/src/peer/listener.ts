/**
 * TCP listener for inbound connections
 */

import * as net from 'node:net';
import { EventEmitter } from 'node:events';
import { Locator, createLocator } from '../types/locator.js';
import { RateLimiter, RateLimiterConfig } from '../utils/rate-limiter.js';

export interface ListenerOptions {
  /** Host to bind to (default: '0.0.0.0') */
  host?: string;
  /** Port to bind to */
  port: number;
  /** Maximum pending connections */
  backlog?: number;
  /** Rate limiter configuration. If provided, connections will be rate limited by IP */
  rateLimiter?: RateLimiterConfig;
}

export interface ListenerEvents {
  connection: [socket: net.Socket, remote: Locator];
  error: [error: Error];
  listening: [locator: Locator];
  close: [];
  rateLimited: [remote: Locator];
}

/**
 * TCP listener that accepts inbound connections
 */
export class Listener extends EventEmitter<ListenerEvents> {
  private server: net.Server;
  private localLocator: Locator | null = null;
  private rateLimiter: RateLimiter | null = null;

  constructor(options: ListenerOptions) {
    super();

    // Initialize rate limiter if configured
    if (options.rateLimiter) {
      this.rateLimiter = new RateLimiter(options.rateLimiter);
    }

    this.server = net.createServer((socket) => {
      const remoteAddress = socket.remoteAddress ?? 'unknown';
      const remote = socket.remoteAddress && socket.remotePort
        ? createLocator(socket.remoteAddress, socket.remotePort)
        : createLocator('unknown', 0);

      // Check rate limit before accepting connection
      if (this.rateLimiter && !this.rateLimiter.isAllowed(remoteAddress)) {
        this.emit('rateLimited', remote);
        socket.destroy();
        return;
      }

      this.emit('connection', socket, remote);
    });

    this.server.on('error', (err) => {
      this.emit('error', err);
    });

    this.server.on('listening', () => {
      const addr = this.server.address();
      if (addr && typeof addr === 'object') {
        this.localLocator = createLocator(
          addr.address === '::' ? '0.0.0.0' : addr.address,
          addr.port
        );
        this.emit('listening', this.localLocator);
      }
    });

    this.server.on('close', () => {
      this.emit('close');
    });

    this.server.listen({
      host: options.host ?? '0.0.0.0',
      port: options.port,
      backlog: options.backlog,
    });
  }

  /**
   * Get the local address the listener is bound to
   */
  get address(): Locator | null {
    return this.localLocator;
  }

  /**
   * Check if the listener is listening
   */
  get listening(): boolean {
    return this.server.listening;
  }

  /**
   * Close the listener
   */
  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      // Clean up rate limiter
      if (this.rateLimiter) {
        this.rateLimiter.stop();
        this.rateLimiter = null;
      }

      this.server.close((err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  /**
   * Get rate limiter statistics (if rate limiting is enabled)
   */
  getRateLimitStats(): { totalKeys: number; totalRequests: number } | null {
    return this.rateLimiter?.getStats() ?? null;
  }

  /**
   * Reset rate limit for a specific IP
   */
  resetRateLimit(ip: string): void {
    this.rateLimiter?.reset(ip);
  }
}

/**
 * Create and start a listener
 */
export function listen(options: ListenerOptions): Listener {
  return new Listener(options);
}
