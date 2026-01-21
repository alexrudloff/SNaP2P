/**
 * Control message construction and helpers
 */

import {
  MessageType,
  VisibilityMode,
  HelloMessage,
  AuthMessage,
  AuthOkMessage,
  AuthFailMessage,
  PingMessage,
  PongMessage,
  ErrorMessage,
} from '../types/messages.js';
import { ErrorCode } from '../types/errors.js';
import { getRandomBytes } from '../crypto/keys.js';

/** Protocol version */
export const PROTOCOL_VERSION = 1;

/** Nonce size in bytes */
const NONCE_SIZE = 32;

/**
 * Create a HELLO message
 */
export function createHelloMessage(
  nodePublicKey: Uint8Array,
  visibility: VisibilityMode = VisibilityMode.PUBLIC
): HelloMessage {
  return {
    type: MessageType.HELLO,
    version: PROTOCOL_VERSION,
    nodePublicKey,
    nonce: getRandomBytes(NONCE_SIZE),
    timestamp: BigInt(Date.now()),
    visibility,
  };
}

/**
 * Create an AUTH message
 */
export function createAuthMessage(
  attestation: Uint8Array,
  handshakeData: Uint8Array
): AuthMessage {
  return {
    type: MessageType.AUTH,
    attestation,
    handshakeData,
  };
}

/**
 * Create an AUTH_OK message
 */
export function createAuthOkMessage(
  principal: string,
  sessionId?: Uint8Array
): AuthOkMessage {
  return {
    type: MessageType.AUTH_OK,
    principal,
    sessionId: sessionId ?? getRandomBytes(32),
  };
}

/**
 * Create an AUTH_FAIL message
 */
export function createAuthFailMessage(
  errorCode: ErrorCode,
  reason?: string
): AuthFailMessage {
  return {
    type: MessageType.AUTH_FAIL,
    errorCode,
    reason,
  };
}

/**
 * Create a PING message
 */
export function createPingMessage(sequence: bigint): PingMessage {
  return {
    type: MessageType.PING,
    sequence,
    timestamp: BigInt(Date.now()),
  };
}

/**
 * Create a PONG message (response to PING)
 */
export function createPongMessage(ping: PingMessage): PongMessage {
  return {
    type: MessageType.PONG,
    sequence: ping.sequence,
    timestamp: BigInt(Date.now()),
  };
}

/**
 * Create an ERROR message
 */
export function createErrorMessage(errorCode: ErrorCode, reason?: string): ErrorMessage {
  return {
    type: MessageType.ERROR,
    errorCode,
    reason,
  };
}

/**
 * Validate a HELLO message
 */
export function validateHelloMessage(msg: HelloMessage): { valid: boolean; error?: string } {
  if (msg.version !== PROTOCOL_VERSION) {
    return { valid: false, error: `Unsupported version: ${msg.version}` };
  }

  if (msg.nodePublicKey.length !== 32) {
    return { valid: false, error: 'Invalid node public key length' };
  }

  if (msg.nonce.length !== NONCE_SIZE) {
    return { valid: false, error: 'Invalid nonce length' };
  }

  // Check timestamp is not too far in the past or future (5 minute tolerance)
  const now = BigInt(Date.now());
  const tolerance = BigInt(5 * 60 * 1000);
  if (msg.timestamp > now + tolerance || msg.timestamp < now - tolerance) {
    return { valid: false, error: 'Timestamp out of acceptable range' };
  }

  return { valid: true };
}
