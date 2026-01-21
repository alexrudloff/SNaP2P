/**
 * TCP listener for inbound connections
 */

import * as net from 'node:net';
import { EventEmitter } from 'node:events';
import { Locator, createLocator } from '../types/locator.js';

export interface ListenerOptions {
  /** Host to bind to (default: '0.0.0.0') */
  host?: string;
  /** Port to bind to */
  port: number;
  /** Maximum pending connections */
  backlog?: number;
}

export interface ListenerEvents {
  connection: [socket: net.Socket, remote: Locator];
  error: [error: Error];
  listening: [locator: Locator];
  close: [];
}

/**
 * TCP listener that accepts inbound connections
 */
export class Listener extends EventEmitter<ListenerEvents> {
  private server: net.Server;
  private localLocator: Locator | null = null;

  constructor(options: ListenerOptions) {
    super();

    this.server = net.createServer((socket) => {
      const remote = socket.remoteAddress && socket.remotePort
        ? createLocator(socket.remoteAddress, socket.remotePort)
        : createLocator('unknown', 0);

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
      this.server.close((err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }
}

/**
 * Create and start a listener
 */
export function listen(options: ListenerOptions): Listener {
  return new Listener(options);
}
