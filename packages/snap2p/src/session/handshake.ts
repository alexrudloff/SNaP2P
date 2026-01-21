/**
 * Session handshake orchestration.
 * Combines Noise XX with SNaP2P HELLO/AUTH protocol.
 *
 * Flow:
 * 1. Noise XX handshake (3 messages over raw TCP)
 * 2. Encrypted HELLO exchange (mutual)
 * 3. Encrypted AUTH exchange (attestations)
 * 4. AUTH_OK/AUTH_FAIL
 */

import * as net from 'node:net';
import { NoiseHandshake, NoiseState, noiseEncrypt, noiseDecrypt, createInitiatorHandshake, createResponderHandshake } from '../crypto/noise.js';
import { NodeKeyPair } from '../crypto/keys.js';
import { FrameBuffer, frameMessage } from '../wire/framing.js';
import { encodeMessage, decodeMessage } from '../wire/codec.js';
import {
  MessageType,
  VisibilityMode,
  HelloMessage,
  AuthMessage,
  AuthOkMessage,
  AuthFailMessage,
  Message,
} from '../types/messages.js';
import { Principal, formatPrincipal } from '../types/principal.js';
import { ErrorCode, SNaP2PError } from '../types/errors.js';
import {
  createHelloMessage,
  createAuthMessage,
  createAuthOkMessage,
  createAuthFailMessage,
  validateHelloMessage,
} from '../control/messages.js';
import {
  NodeKeyAttestation,
  serializeAttestation,
  deserializeAttestation,
  verifyAttestation,
} from '../identity/attestation.js';

export interface HandshakeConfig {
  /** Timeout for handshake completion in ms */
  timeoutMs?: number;
  /** Visibility mode to advertise */
  visibility?: VisibilityMode;
  /** Optional allowlist of principals (for Private/Stealth) */
  allowlist?: Set<string>;
}

export interface HandshakeResult {
  /** Noise state for encrypted communication */
  noiseState: NoiseState;
  /** Remote peer's principal */
  remotePrincipal: Principal;
  /** Remote peer's attestation */
  remoteAttestation: NodeKeyAttestation;
  /** Session ID */
  sessionId: Uint8Array;
}

const DEFAULT_TIMEOUT = 30000;

/**
 * Read a complete frame from socket
 */
function readFrame(socket: net.Socket, frameBuffer: FrameBuffer, timeout: number): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      cleanup();
      reject(new SNaP2PError(ErrorCode.ERR_TIMEOUT, 'Read timeout'));
    }, timeout);

    const cleanup = () => {
      clearTimeout(timeoutId);
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
    };

    const tryRead = () => {
      const frame = frameBuffer.readFrame();
      if (frame) {
        cleanup();
        resolve(frame);
        return true;
      }
      return false;
    };

    const onData = (data: Buffer) => {
      frameBuffer.append(new Uint8Array(data));
      tryRead();
    };

    const onError = (err: Error) => {
      cleanup();
      reject(new SNaP2PError(ErrorCode.ERR_HANDSHAKE_FAILED, err.message));
    };

    const onClose = () => {
      cleanup();
      reject(new SNaP2PError(ErrorCode.ERR_CONNECTION_CLOSED, 'Connection closed'));
    };

    // Check if we already have a complete frame
    if (tryRead()) return;

    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
  });
}

/**
 * Send a framed message
 */
function sendFrame(socket: net.Socket, data: Uint8Array): void {
  socket.write(frameMessage(data));
}

/**
 * Perform Noise XX handshake
 */
async function performNoiseHandshake(
  socket: net.Socket,
  noise: NoiseHandshake,
  frameBuffer: FrameBuffer,
  timeout: number
): Promise<NoiseState> {
  if (noise.initiator) {
    // Initiator: -> e
    const msg1 = noise.writeMessage();
    sendFrame(socket, msg1);

    // Initiator: <- e, ee, s, es
    const msg2 = await readFrame(socket, frameBuffer, timeout);
    noise.readMessage(msg2);

    // Initiator: -> s, se
    const msg3 = noise.writeMessage();
    sendFrame(socket, msg3);
  } else {
    // Responder: <- e
    const msg1 = await readFrame(socket, frameBuffer, timeout);
    noise.readMessage(msg1);

    // Responder: -> e, ee, s, es
    const msg2 = noise.writeMessage();
    sendFrame(socket, msg2);

    // Responder: <- s, se
    const msg3 = await readFrame(socket, frameBuffer, timeout);
    noise.readMessage(msg3);
  }

  return noise.finalize();
}

/**
 * Send an encrypted message
 */
function sendEncrypted(socket: net.Socket, noiseState: NoiseState, message: Message): void {
  const encoded = encodeMessage(message);
  const encrypted = noiseEncrypt(noiseState.sendCipher, encoded);
  sendFrame(socket, encrypted);
}

/**
 * Read and decrypt a message
 */
async function readEncrypted(
  socket: net.Socket,
  noiseState: NoiseState,
  frameBuffer: FrameBuffer,
  timeout: number
): Promise<Message> {
  const encrypted = await readFrame(socket, frameBuffer, timeout);
  const decrypted = noiseDecrypt(noiseState.recvCipher, encrypted);
  return decodeMessage(decrypted);
}

/**
 * Perform handshake as initiator (client)
 */
export async function performInitiatorHandshake(
  socket: net.Socket,
  nodeKeys: NodeKeyPair,
  attestation: NodeKeyAttestation,
  config: HandshakeConfig = {}
): Promise<HandshakeResult> {
  const timeout = config.timeoutMs ?? DEFAULT_TIMEOUT;
  const visibility = config.visibility ?? VisibilityMode.PUBLIC;
  const frameBuffer = new FrameBuffer();

  // Step 1: Noise XX handshake
  const noise = createInitiatorHandshake(nodeKeys.x25519PrivateKey, nodeKeys.x25519PublicKey);
  const noiseState = await performNoiseHandshake(socket, noise, frameBuffer, timeout);

  // Step 2: Send encrypted HELLO
  const hello = createHelloMessage(nodeKeys.publicKey, visibility);
  sendEncrypted(socket, noiseState, hello);

  // Step 3: Receive encrypted HELLO
  const remoteHello = await readEncrypted(socket, noiseState, frameBuffer, timeout);
  if (remoteHello.type !== MessageType.HELLO) {
    throw new SNaP2PError(ErrorCode.ERR_INVALID_MESSAGE, 'Expected HELLO');
  }
  const validation = validateHelloMessage(remoteHello as HelloMessage);
  if (!validation.valid) {
    throw new SNaP2PError(ErrorCode.ERR_INVALID_MESSAGE, validation.error);
  }

  // Step 4: Send encrypted AUTH with attestation
  const attestationBytes = serializeAttestation(attestation);
  const auth = createAuthMessage(attestationBytes, new Uint8Array(0));
  sendEncrypted(socket, noiseState, auth);

  // Step 5: Receive encrypted AUTH
  const remoteAuth = await readEncrypted(socket, noiseState, frameBuffer, timeout);
  if (remoteAuth.type !== MessageType.AUTH) {
    throw new SNaP2PError(ErrorCode.ERR_INVALID_MESSAGE, 'Expected AUTH');
  }
  const remoteAttestation = deserializeAttestation((remoteAuth as AuthMessage).attestation);
  const verifyResult = verifyAttestation(remoteAttestation);
  if (!verifyResult.valid) {
    throw new SNaP2PError(ErrorCode.ERR_ATTESTATION_INVALID, verifyResult.error);
  }

  // Step 6: Receive AUTH_OK or AUTH_FAIL
  const authResponse = await readEncrypted(socket, noiseState, frameBuffer, timeout);
  if (authResponse.type === MessageType.AUTH_FAIL) {
    const fail = authResponse as AuthFailMessage;
    throw new SNaP2PError(fail.errorCode, fail.reason);
  }
  if (authResponse.type !== MessageType.AUTH_OK) {
    throw new SNaP2PError(ErrorCode.ERR_INVALID_MESSAGE, 'Expected AUTH_OK or AUTH_FAIL');
  }
  const authOk = authResponse as AuthOkMessage;

  // Step 7: Send AUTH_OK
  const ourAuthOk = createAuthOkMessage(formatPrincipal(attestation.principal), authOk.sessionId);
  sendEncrypted(socket, noiseState, ourAuthOk);

  return {
    noiseState,
    remotePrincipal: remoteAttestation.principal,
    remoteAttestation,
    sessionId: authOk.sessionId,
  };
}

/**
 * Perform handshake as responder (server)
 */
export async function performResponderHandshake(
  socket: net.Socket,
  nodeKeys: NodeKeyPair,
  attestation: NodeKeyAttestation,
  config: HandshakeConfig = {}
): Promise<HandshakeResult> {
  const timeout = config.timeoutMs ?? DEFAULT_TIMEOUT;
  const visibility = config.visibility ?? VisibilityMode.PUBLIC;
  const allowlist = config.allowlist;
  const frameBuffer = new FrameBuffer();

  // Step 1: Noise XX handshake
  const noise = createResponderHandshake(nodeKeys.x25519PrivateKey, nodeKeys.x25519PublicKey);
  const noiseState = await performNoiseHandshake(socket, noise, frameBuffer, timeout);

  // Step 2: Receive encrypted HELLO
  const remoteHello = await readEncrypted(socket, noiseState, frameBuffer, timeout);
  if (remoteHello.type !== MessageType.HELLO) {
    throw new SNaP2PError(ErrorCode.ERR_INVALID_MESSAGE, 'Expected HELLO');
  }
  const validation = validateHelloMessage(remoteHello as HelloMessage);
  if (!validation.valid) {
    throw new SNaP2PError(ErrorCode.ERR_INVALID_MESSAGE, validation.error);
  }

  // Step 3: Send encrypted HELLO
  const hello = createHelloMessage(nodeKeys.publicKey, visibility);
  sendEncrypted(socket, noiseState, hello);

  // Step 4: Receive encrypted AUTH
  const remoteAuth = await readEncrypted(socket, noiseState, frameBuffer, timeout);
  if (remoteAuth.type !== MessageType.AUTH) {
    throw new SNaP2PError(ErrorCode.ERR_INVALID_MESSAGE, 'Expected AUTH');
  }
  const remoteAttestation = deserializeAttestation((remoteAuth as AuthMessage).attestation);
  const verifyResult = verifyAttestation(remoteAttestation);

  if (!verifyResult.valid) {
    const authFail = createAuthFailMessage(ErrorCode.ERR_ATTESTATION_INVALID, verifyResult.error);
    sendEncrypted(socket, noiseState, authFail);
    throw new SNaP2PError(ErrorCode.ERR_ATTESTATION_INVALID, verifyResult.error);
  }

  // Check allowlist
  const remotePrincipalStr = formatPrincipal(remoteAttestation.principal);
  if (allowlist && !allowlist.has(remotePrincipalStr)) {
    const authFail = createAuthFailMessage(ErrorCode.ERR_NOT_ALLOWED, 'Not on allowlist');
    sendEncrypted(socket, noiseState, authFail);
    throw new SNaP2PError(ErrorCode.ERR_NOT_ALLOWED, 'Remote peer not on allowlist');
  }

  // Step 5: Send encrypted AUTH
  const attestationBytes = serializeAttestation(attestation);
  const auth = createAuthMessage(attestationBytes, new Uint8Array(0));
  sendEncrypted(socket, noiseState, auth);

  // Step 6: Send AUTH_OK
  const sessionId = new Uint8Array(32);
  crypto.getRandomValues(sessionId);
  const authOk = createAuthOkMessage(formatPrincipal(attestation.principal), sessionId);
  sendEncrypted(socket, noiseState, authOk);

  // Step 7: Receive AUTH_OK
  const remoteAuthOk = await readEncrypted(socket, noiseState, frameBuffer, timeout);
  if (remoteAuthOk.type !== MessageType.AUTH_OK) {
    throw new SNaP2PError(ErrorCode.ERR_INVALID_MESSAGE, 'Expected AUTH_OK');
  }

  return {
    noiseState,
    remotePrincipal: remoteAttestation.principal,
    remoteAttestation,
    sessionId,
  };
}
