/**
 * Session management for established connections
 */

import * as net from 'node:net';
import { EventEmitter } from 'node:events';
import { NoiseState, noiseEncrypt, noiseDecrypt } from '../crypto/noise.js';
import { FrameBuffer, frameMessage } from '../wire/framing.js';
import { encodeMessage, decodeMessage } from '../wire/codec.js';
import { Message, MessageType, StreamDataMessage } from '../types/messages.js';
import { Principal, formatPrincipal } from '../types/principal.js';
import { ErrorCode, SNaP2PError } from '../types/errors.js';
import { KeepaliveManager } from '../control/keepalive.js';
import { NodeKeyAttestation } from '../identity/attestation.js';

export interface SessionConfig {
  /** Enable keepalive pings */
  keepalive?: boolean;
  /** Keepalive interval in ms */
  keepaliveIntervalMs?: number;
}

export interface SessionEvents {
  message: [message: Message];
  stream: [streamId: bigint, label?: string];
  streamData: [streamId: bigint, data: Uint8Array, fin: boolean];
  streamClose: [streamId: bigint, errorCode?: ErrorCode];
  error: [error: Error];
  close: [];
}

/**
 * An authenticated session with a remote peer
 */
export class Session extends EventEmitter<SessionEvents> {
  private socket: net.Socket;
  private noiseState: NoiseState;
  private frameBuffer: FrameBuffer;
  private keepalive: KeepaliveManager | null = null;
  private closed: boolean = false;

  readonly localPrincipal: Principal;
  readonly remotePrincipal: Principal;
  readonly remoteAttestation: NodeKeyAttestation;
  readonly sessionId: Uint8Array;
  readonly isInitiator: boolean;

  constructor(
    socket: net.Socket,
    noiseState: NoiseState,
    localPrincipal: Principal,
    remotePrincipal: Principal,
    remoteAttestation: NodeKeyAttestation,
    sessionId: Uint8Array,
    isInitiator: boolean,
    config: SessionConfig = {}
  ) {
    super();

    this.socket = socket;
    this.noiseState = noiseState;
    this.localPrincipal = localPrincipal;
    this.remotePrincipal = remotePrincipal;
    this.remoteAttestation = remoteAttestation;
    this.sessionId = sessionId;
    this.isInitiator = isInitiator;
    this.frameBuffer = new FrameBuffer();

    // Set up socket handlers
    this.socket.on('data', this.handleData.bind(this));
    this.socket.on('error', this.handleError.bind(this));
    this.socket.on('close', this.handleClose.bind(this));

    // Set up keepalive if enabled
    if (config.keepalive !== false) {
      this.keepalive = new KeepaliveManager(
        (ping) => this.sendMessage(ping),
        () => this.close(ErrorCode.ERR_TIMEOUT),
        { intervalMs: config.keepaliveIntervalMs }
      );
      this.keepalive.start();
    }
  }

  /**
   * Send a control message
   * Returns false if the session is closed
   */
  sendMessage(message: Message): boolean {
    if (this.closed) {
      return false;
    }

    try {
      const encoded = encodeMessage(message);
      const encrypted = noiseEncrypt(this.noiseState.sendCipher, encoded);
      const framed = frameMessage(encrypted);
      this.socket.write(framed);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Send stream data
   * Returns false if the session is closed
   */
  sendStreamData(streamId: bigint, data: Uint8Array, fin: boolean = false): boolean {
    const message: StreamDataMessage = {
      type: MessageType.STREAM_DATA,
      streamId,
      data,
      fin: fin || undefined,
    };
    return this.sendMessage(message);
  }

  /**
   * Close the session
   */
  close(errorCode?: ErrorCode): void {
    if (this.closed) {
      return;
    }
    this.closed = true;

    if (this.keepalive) {
      this.keepalive.stop();
    }

    this.socket.destroy();
    this.emit('close');
  }

  /**
   * Check if session is open
   */
  get isOpen(): boolean {
    return !this.closed;
  }

  /**
   * Get the handshake hash for channel binding
   */
  get handshakeHash(): Uint8Array {
    return this.noiseState.handshakeHash;
  }

  private handleData(data: Buffer): void {
    this.frameBuffer.append(new Uint8Array(data));

    let frame: Uint8Array | null;
    while ((frame = this.frameBuffer.readFrame()) !== null) {
      try {
        const decrypted = noiseDecrypt(this.noiseState.recvCipher, frame);
        const message = decodeMessage(decrypted);
        this.handleMessage(message);
      } catch (err) {
        this.emit('error', err instanceof Error ? err : new Error(String(err)));
      }
    }
  }

  private handleMessage(message: Message): void {
    switch (message.type) {
      case MessageType.PING:
        if (this.keepalive) {
          const pong = this.keepalive.createPongResponse(message);
          this.sendMessage(pong);
        }
        break;

      case MessageType.PONG:
        if (this.keepalive) {
          this.keepalive.handlePong(message);
        }
        break;

      case MessageType.OPEN_STREAM:
        this.emit('stream', message.streamId, message.label);
        break;

      case MessageType.STREAM_DATA:
        this.emit('streamData', message.streamId, message.data, message.fin ?? false);
        break;

      case MessageType.CLOSE_STREAM:
        this.emit('streamClose', message.streamId, message.errorCode);
        break;

      case MessageType.ERROR:
        this.emit('error', new SNaP2PError(message.errorCode, message.reason));
        break;

      default:
        this.emit('message', message);
    }
  }

  private handleError(err: Error): void {
    this.emit('error', err);
  }

  private handleClose(): void {
    if (!this.closed) {
      this.closed = true;
      if (this.keepalive) {
        this.keepalive.stop();
      }
      this.emit('close');
    }
  }
}
