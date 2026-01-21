/**
 * TCP dialer for outbound connections
 */

import * as net from 'node:net';
import { Locator } from '../types/locator.js';
import { SNaP2PError, ErrorCode } from '../types/errors.js';

export interface DialOptions {
  /** Connection timeout in milliseconds */
  timeout?: number;
}

const DEFAULT_TIMEOUT = 10000; // 10 seconds

/**
 * Dial a TCP connection to a peer
 */
export function dial(locator: Locator, options: DialOptions = {}): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout ?? DEFAULT_TIMEOUT;

    if (locator.transport !== 'tcp') {
      reject(new SNaP2PError(ErrorCode.ERR_UNKNOWN, `Unsupported transport: ${locator.transport}`));
      return;
    }

    const socket = new net.Socket();
    let connected = false;

    const timeoutId = setTimeout(() => {
      if (!connected) {
        socket.destroy();
        reject(new SNaP2PError(ErrorCode.ERR_TIMEOUT, `Connection timeout after ${timeout}ms`));
      }
    }, timeout);

    socket.on('connect', () => {
      connected = true;
      clearTimeout(timeoutId);
      resolve(socket);
    });

    socket.on('error', (err) => {
      clearTimeout(timeoutId);
      if (!connected) {
        reject(new SNaP2PError(ErrorCode.ERR_CONNECTION_CLOSED, `Connection failed: ${err.message}`));
      }
    });

    socket.connect(locator.port, locator.host);
  });
}

/**
 * Create a socket with common options configured
 */
export function configureSocket(socket: net.Socket): void {
  // Enable keep-alive
  socket.setKeepAlive(true, 30000);
  // Disable Nagle's algorithm for lower latency
  socket.setNoDelay(true);
}
