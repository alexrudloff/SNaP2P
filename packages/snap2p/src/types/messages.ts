/**
 * Control plane message types for SNaP2P protocol.
 * All messages are length-prefixed and self-delimiting.
 */

import { ErrorCode } from './errors.js';

/**
 * Message type identifiers
 */
export enum MessageType {
  HELLO = 0x01,
  AUTH = 0x02,
  AUTH_OK = 0x03,
  AUTH_FAIL = 0x04,
  OPEN_STREAM = 0x10,
  CLOSE_STREAM = 0x11,
  STREAM_DATA = 0x12,
  PING = 0x20,
  PONG = 0x21,
  KNOCK = 0x30,
  KNOCK_RESPONSE = 0x31,
  ERROR = 0xff,
}

/**
 * Visibility modes for peers
 */
export enum VisibilityMode {
  PUBLIC = 0,
  PRIVATE = 1,
  STEALTH = 2,
}

/**
 * Base interface for all messages
 */
export interface BaseMessage {
  readonly type: MessageType;
}

/**
 * Capability flags for HELLO message per SPECS 3.2.1
 */
export enum Capability {
  /** Supports stealth mode */
  STEALTH = 'stealth',
  /** Supports aliases module */
  ALIASES = 'aliases',
  /** Supports PX-1 discovery */
  PX1 = 'px1',
}

/**
 * HELLO message - initial handshake message
 * Per SPECS 3.2.1
 */
export interface HelloMessage extends BaseMessage {
  readonly type: MessageType.HELLO;
  readonly version: number;
  readonly nodePublicKey: Uint8Array;
  readonly nonce: Uint8Array;
  readonly timestamp: bigint;
  readonly visibility: VisibilityMode;
  /** Framework feature flags per SPECS 3.2.1 */
  readonly capabilities: string[];
}

/**
 * AUTH message - contains NodeKeyAttestation
 */
export interface AuthMessage extends BaseMessage {
  readonly type: MessageType.AUTH;
  readonly attestation: Uint8Array;
  readonly handshakeData: Uint8Array;
}

/**
 * AUTH_OK message - authentication succeeded
 */
export interface AuthOkMessage extends BaseMessage {
  readonly type: MessageType.AUTH_OK;
  readonly principal: string;
  readonly sessionId: Uint8Array;
}

/**
 * AUTH_FAIL message - authentication failed
 */
export interface AuthFailMessage extends BaseMessage {
  readonly type: MessageType.AUTH_FAIL;
  readonly errorCode: ErrorCode;
  readonly reason?: string;
}

/**
 * OPEN_STREAM message - request to open a new stream
 */
export interface OpenStreamMessage extends BaseMessage {
  readonly type: MessageType.OPEN_STREAM;
  readonly streamId: bigint;
  readonly label?: string;
}

/**
 * CLOSE_STREAM message - request to close a stream
 */
export interface CloseStreamMessage extends BaseMessage {
  readonly type: MessageType.CLOSE_STREAM;
  readonly streamId: bigint;
  readonly errorCode?: ErrorCode;
}

/**
 * STREAM_DATA message - data frame for a stream
 */
export interface StreamDataMessage extends BaseMessage {
  readonly type: MessageType.STREAM_DATA;
  readonly streamId: bigint;
  readonly data: Uint8Array;
  readonly fin?: boolean;
}

/**
 * PING message - keepalive request
 */
export interface PingMessage extends BaseMessage {
  readonly type: MessageType.PING;
  readonly sequence: bigint;
  readonly timestamp: bigint;
}

/**
 * PONG message - keepalive response
 */
export interface PongMessage extends BaseMessage {
  readonly type: MessageType.PONG;
  readonly sequence: bigint;
  readonly timestamp: bigint;
}

/**
 * KNOCK message - stealth mode pre-auth
 */
export interface KnockMessage extends BaseMessage {
  readonly type: MessageType.KNOCK;
  readonly inviteToken: Uint8Array;
}

/**
 * KNOCK_RESPONSE message - response to KNOCK
 */
export interface KnockResponseMessage extends BaseMessage {
  readonly type: MessageType.KNOCK_RESPONSE;
  readonly allowed: boolean;
}

/**
 * ERROR message - generic error
 */
export interface ErrorMessage extends BaseMessage {
  readonly type: MessageType.ERROR;
  readonly errorCode: ErrorCode;
  readonly reason?: string;
}

/**
 * Union type of all messages
 */
export type Message =
  | HelloMessage
  | AuthMessage
  | AuthOkMessage
  | AuthFailMessage
  | OpenStreamMessage
  | CloseStreamMessage
  | StreamDataMessage
  | PingMessage
  | PongMessage
  | KnockMessage
  | KnockResponseMessage
  | ErrorMessage;
