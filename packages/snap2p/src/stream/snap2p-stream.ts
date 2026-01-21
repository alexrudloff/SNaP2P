/**
 * SNaP2PStream - A bidirectional byte stream within a session.
 * Implements Node.js Duplex stream interface with backpressure.
 */

import { Duplex, DuplexOptions } from 'node:stream';
import { ErrorCode } from '../types/errors.js';

export interface StreamOptions extends DuplexOptions {
  /** Stream ID */
  streamId: bigint;
  /** Optional label for routing/debugging */
  label?: string;
  /** Callback to send data to the session */
  onSend: (streamId: bigint, data: Uint8Array, fin: boolean) => void;
  /** Callback to close the stream */
  onClose: (streamId: bigint, errorCode?: ErrorCode) => void;
}

/**
 * A multiplexed bidirectional stream
 */
export class SNaP2PStream extends Duplex {
  readonly streamId: bigint;
  readonly label?: string;

  private onSend: (streamId: bigint, data: Uint8Array, fin: boolean) => void;
  private onCloseCallback: (streamId: bigint, errorCode?: ErrorCode) => void;
  private writeClosed: boolean = false;
  private readClosed: boolean = false;

  constructor(options: StreamOptions) {
    super({
      ...options,
      // Use reasonable defaults for P2P streaming
      highWaterMark: options.highWaterMark ?? 64 * 1024, // 64KB
    });

    this.streamId = options.streamId;
    this.label = options.label;
    this.onSend = options.onSend;
    this.onCloseCallback = options.onClose;
  }

  /**
   * Called when data is written to the stream
   */
  _write(chunk: Buffer | Uint8Array, _encoding: string, callback: (error?: Error | null) => void): void {
    if (this.writeClosed) {
      callback(new Error('Stream write side closed'));
      return;
    }

    try {
      const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
      this.onSend(this.streamId, data, false);
      callback();
    } catch (err) {
      callback(err instanceof Error ? err : new Error(String(err)));
    }
  }

  /**
   * Called when the writable side is finished
   */
  _final(callback: (error?: Error | null) => void): void {
    if (!this.writeClosed) {
      this.writeClosed = true;
      try {
        // Send empty data with fin flag
        this.onSend(this.streamId, new Uint8Array(0), true);
      } catch (err) {
        callback(err instanceof Error ? err : new Error(String(err)));
        return;
      }
    }
    callback();
  }

  /**
   * Called when reading from the stream
   */
  _read(_size: number): void {
    // Data is pushed from external source via pushData()
  }

  /**
   * Called when the stream is destroyed
   */
  _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    if (!this.writeClosed) {
      this.writeClosed = true;
    }
    if (!this.readClosed) {
      this.readClosed = true;
    }

    const errorCode = error ? ErrorCode.ERR_INTERNAL : undefined;
    this.onCloseCallback(this.streamId, errorCode);
    callback(error);
  }

  /**
   * Push received data into the stream
   */
  pushData(data: Uint8Array, fin: boolean): void {
    if (this.readClosed) {
      return;
    }

    if (data.length > 0) {
      const shouldContinue = this.push(Buffer.from(data));
      if (!shouldContinue) {
        // Backpressure - the stream buffer is full
        // In a full implementation, we'd signal flow control to the sender
      }
    }

    if (fin) {
      this.readClosed = true;
      this.push(null); // Signal EOF
    }
  }

  /**
   * Called when remote closes the stream
   */
  remoteClose(_errorCode?: ErrorCode): void {
    // Close gracefully regardless of error code
    // The caller can check the error code if needed
    if (!this.readClosed) {
      this.readClosed = true;
      this.push(null);
    }

    if (!this.writeClosed) {
      this.writeClosed = true;
    }
  }

  /**
   * Close the write side of the stream
   */
  closeWrite(): void {
    if (!this.writeClosed) {
      this.end();
    }
  }

  /**
   * Check if the stream is fully closed
   */
  get isClosed(): boolean {
    return this.writeClosed && this.readClosed;
  }
}
