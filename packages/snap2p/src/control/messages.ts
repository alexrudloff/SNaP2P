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
 * Per SPECS 3.2.1 - includes capabilities list
 */
export function createHelloMessage(
  nodePublicKey: Uint8Array,
  visibility: VisibilityMode = VisibilityMode.PUBLIC,
  capabilities: string[] = []
): HelloMessage {
  return {
    type: MessageType.HELLO,
    version: PROTOCOL_VERSION,
    nodePublicKey,
    nonce: getRandomBytes(NONCE_SIZE),
    timestamp: BigInt(Math.floor(Date.now() / 1000)), // Unix seconds per SPECS 3.0
    visibility,
    capabilities,
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
    timestamp: BigInt(Math.floor(Date.now() / 1000)), // Unix seconds per SPECS 3.0
  };
}

/**
 * Create a PONG message (response to PING)
 */
export function createPongMessage(ping: PingMessage): PongMessage {
  return {
    type: MessageType.PONG,
    sequence: ping.sequence,
    timestamp: BigInt(Math.floor(Date.now() / 1000)), // Unix seconds per SPECS 3.0
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
 * Per SPECS 2.6 - clock skew tolerance ±5 minutes
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

  // Check timestamp is not too far in the past or future (5 minute tolerance per SPECS 2.6)
  const now = BigInt(Math.floor(Date.now() / 1000)); // Unix seconds per SPECS 3.0
  const tolerance = BigInt(5 * 60); // 5 minutes in seconds
  if (msg.timestamp > now + tolerance || msg.timestamp < now - tolerance) {
    return { valid: false, error: 'Timestamp out of acceptable range' };
  }

  // Validate capabilities is an array (can be empty)
  if (!Array.isArray(msg.capabilities)) {
    return { valid: false, error: 'Capabilities must be an array' };
  }

  return { valid: true };
}
