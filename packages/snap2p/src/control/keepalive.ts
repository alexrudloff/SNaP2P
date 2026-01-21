/**
 * Keepalive (PING/PONG) management
 */

import { createPingMessage, createPongMessage } from './messages.js';
import { PingMessage, PongMessage } from '../types/messages.js';

export interface KeepaliveConfig {
  /** Interval between pings in ms (default: 30000) */
  intervalMs?: number;
  /** Timeout waiting for pong in ms (default: 10000) */
  timeoutMs?: number;
}

/**
 * Keepalive state manager
 */
export class KeepaliveManager {
  private sequence: bigint = 0n;
  private pendingPings: Map<bigint, { timestamp: bigint; timer: NodeJS.Timeout }> = new Map();
  private intervalTimer: NodeJS.Timeout | null = null;
  private config: Required<KeepaliveConfig>;

  private onPing: (ping: PingMessage) => void;
  private onTimeout: () => void;

  constructor(
    onPing: (ping: PingMessage) => void,
    onTimeout: () => void,
    config: KeepaliveConfig = {}
  ) {
    this.onPing = onPing;
    this.onTimeout = onTimeout;
    this.config = {
      intervalMs: config.intervalMs ?? 30000,
      timeoutMs: config.timeoutMs ?? 10000,
    };
  }

  /**
   * Start sending periodic pings
   */
  start(): void {
    if (this.intervalTimer) {
      return;
    }

    this.sendPing();
    this.intervalTimer = setInterval(() => {
      this.sendPing();
    }, this.config.intervalMs);
  }

  /**
   * Stop sending pings
   */
  stop(): void {
    if (this.intervalTimer) {
      clearInterval(this.intervalTimer);
      this.intervalTimer = null;
    }

    for (const { timer } of this.pendingPings.values()) {
      clearTimeout(timer);
    }
    this.pendingPings.clear();
  }

  /**
   * Handle an incoming PONG message
   */
  handlePong(pong: PongMessage): { latencyMs: number } | null {
    const pending = this.pendingPings.get(pong.sequence);
    if (!pending) {
      return null;
    }

    clearTimeout(pending.timer);
    this.pendingPings.delete(pong.sequence);

    const latencyMs = Number(BigInt(Date.now()) - pending.timestamp);
    return { latencyMs };
  }

  /**
   * Create a PONG response for an incoming PING
   */
  createPongResponse(ping: PingMessage): PongMessage {
    return createPongMessage(ping);
  }

  private sendPing(): void {
    const ping = createPingMessage(this.sequence);
    this.sequence++;

    const timer = setTimeout(() => {
      this.pendingPings.delete(ping.sequence);
      this.onTimeout();
    }, this.config.timeoutMs);

    this.pendingPings.set(ping.sequence, {
      timestamp: ping.timestamp,
      timer,
    });

    this.onPing(ping);
  }
}
