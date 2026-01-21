/**
 * Stream multiplexer for managing multiple streams over a session
 */

import { EventEmitter } from 'node:events';
import { SNaP2PStream } from './snap2p-stream.js';
import { Session } from '../session/session.js';
import { ErrorCode, SNaP2PError } from '../types/errors.js';
import { createOpenStreamMessage, createCloseStreamMessage } from '../control/stream-control.js';

export interface MultiplexerEvents {
  stream: [stream: SNaP2PStream];
  error: [error: Error];
}

export interface MultiplexerConfig {
  /** Maximum number of concurrent streams */
  maxStreams?: number;
}

/**
 * Manages multiple streams over a single session
 */
export class Multiplexer extends EventEmitter<MultiplexerEvents> {
  private session: Session;
  private streams: Map<bigint, SNaP2PStream> = new Map();
  private nextStreamId: bigint;
  private config: Required<MultiplexerConfig>;

  constructor(session: Session, config: MultiplexerConfig = {}) {
    super();

    this.session = session;
    this.config = {
      maxStreams: config.maxStreams ?? 100,
    };

    // Initiator uses even IDs, responder uses odd IDs
    this.nextStreamId = session.isInitiator ? 0n : 1n;

    // Set up session event handlers
    this.session.on('stream', this.handleStreamOpen.bind(this));
    this.session.on('streamData', this.handleStreamData.bind(this));
    this.session.on('streamClose', this.handleStreamClose.bind(this));
    this.session.on('error', (err) => this.emit('error', err));
  }

  /**
   * Open a new stream
   */
  openStream(label?: string): SNaP2PStream {
    if (this.streams.size >= this.config.maxStreams) {
      throw new SNaP2PError(ErrorCode.ERR_RESOURCE_EXHAUSTED, 'Maximum streams reached');
    }

    const streamId = this.nextStreamId;
    this.nextStreamId += 2n; // Keep even/odd parity

    const stream = this.createStream(streamId, label);
    this.streams.set(streamId, stream);

    // Send OPEN_STREAM message
    const openMsg = createOpenStreamMessage(streamId, label);
    this.session.sendMessage(openMsg);

    return stream;
  }

  /**
   * Get an existing stream by ID
   */
  getStream(streamId: bigint): SNaP2PStream | undefined {
    return this.streams.get(streamId);
  }

  /**
   * Get all active streams
   */
  getAllStreams(): SNaP2PStream[] {
    return Array.from(this.streams.values());
  }

  /**
   * Close all streams
   */
  closeAll(): void {
    for (const stream of this.streams.values()) {
      stream.destroy();
    }
    this.streams.clear();
  }

  /**
   * Number of active streams
   */
  get streamCount(): number {
    return this.streams.size;
  }

  private createStream(streamId: bigint, label?: string): SNaP2PStream {
    const stream = new SNaP2PStream({
      streamId,
      label,
      onSend: (id, data, fin) => {
        this.session.sendStreamData(id, data, fin);
      },
      onClose: (id, errorCode) => {
        const closeMsg = createCloseStreamMessage(id, errorCode);
        this.session.sendMessage(closeMsg);
        this.streams.delete(id);
      },
    });

    // Only emit unexpected errors - normal stream closes are handled gracefully
    stream.on('error', (err) => {
      // Check if this error is from a stream that's already being closed
      if (!this.streams.has(streamId)) {
        return; // Stream already removed, ignore error
      }
      this.emit('error', err);
    });

    return stream;
  }

  private handleStreamOpen(streamId: bigint, label?: string): void {
    if (this.streams.has(streamId)) {
      // Stream already exists, this is an error
      const closeMsg = createCloseStreamMessage(streamId, ErrorCode.ERR_STREAM_ID_IN_USE);
      this.session.sendMessage(closeMsg);
      return;
    }

    if (this.streams.size >= this.config.maxStreams) {
      const closeMsg = createCloseStreamMessage(streamId, ErrorCode.ERR_RESOURCE_EXHAUSTED);
      this.session.sendMessage(closeMsg);
      return;
    }

    const stream = this.createStream(streamId, label);
    this.streams.set(streamId, stream);
    this.emit('stream', stream);
  }

  private handleStreamData(streamId: bigint, data: Uint8Array, fin: boolean): void {
    const stream = this.streams.get(streamId);
    if (!stream) {
      // Unknown stream, send close
      const closeMsg = createCloseStreamMessage(streamId, ErrorCode.ERR_STREAM_NOT_FOUND);
      this.session.sendMessage(closeMsg);
      return;
    }

    stream.pushData(data, fin);
  }

  private handleStreamClose(streamId: bigint, errorCode?: ErrorCode): void {
    const stream = this.streams.get(streamId);
    if (!stream) {
      return;
    }

    stream.remoteClose(errorCode);
    this.streams.delete(streamId);
  }
}
