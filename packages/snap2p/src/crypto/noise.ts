/**
 * Noise XX handshake implementation for SNaP2P.
 *
 * XX pattern: -> e, <- e, ee, s, es, -> s, se
 * - Both parties authenticate with static keys
 * - No pre-shared knowledge required
 * - Forward secrecy via ephemeral keys
 */

import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { x25519DH, getRandomBytes } from './keys.js';
import { x25519 } from '@noble/curves/ed25519';

/** Noise protocol name for XX with X25519 and ChaCha20-Poly1305 */
const PROTOCOL_NAME = 'Noise_XX_25519_ChaChaPoly_SHA256';

/** Empty byte array for padding */
const EMPTY = new Uint8Array(0);

/**
 * Maximum nonce value before overflow.
 * Per R5/L1: Defense-in-depth check to prevent nonce reuse.
 * ChaCha20-Poly1305 uses a 64-bit nonce counter.
 */
const MAX_NONCE = BigInt(2) ** BigInt(64) - BigInt(1);

/**
 * Cipher state for encrypting/decrypting after handshake
 */
export interface NoiseCipherState {
  /** Encryption key (32 bytes) */
  readonly key: Uint8Array;
  /** Nonce counter */
  nonce: bigint;
}

/**
 * Full noise state after handshake completion
 */
export interface NoiseState {
  /** Cipher state for sending */
  readonly sendCipher: NoiseCipherState;
  /** Cipher state for receiving */
  readonly recvCipher: NoiseCipherState;
  /** Remote static public key (X25519) */
  readonly remoteStaticKey: Uint8Array;
  /** Handshake hash for channel binding */
  readonly handshakeHash: Uint8Array;
}

/**
 * Internal symmetric state during handshake
 */
interface SymmetricState {
  h: Uint8Array;  // handshake hash
  ck: Uint8Array; // chaining key
  k: Uint8Array | null; // encryption key
  n: bigint; // nonce
}

/**
 * Noise XX handshake state machine
 */
export class NoiseHandshake {
  private symmetricState: SymmetricState;
  private localEphemeral: { privateKey: Uint8Array; publicKey: Uint8Array };
  private remoteEphemeral: Uint8Array | null = null;
  private localStatic: { privateKey: Uint8Array; publicKey: Uint8Array };
  private remoteStatic: Uint8Array | null = null;
  private isInitiator: boolean;
  private messageIndex: number = 0;

  constructor(
    localStaticPrivateKey: Uint8Array,
    localStaticPublicKey: Uint8Array,
    isInitiator: boolean
  ) {
    this.isInitiator = isInitiator;
    this.localStatic = {
      privateKey: localStaticPrivateKey,
      publicKey: localStaticPublicKey,
    };

    // Generate ephemeral keypair
    const ephPrivate = getRandomBytes(32);
    this.localEphemeral = {
      privateKey: ephPrivate,
      publicKey: x25519.getPublicKey(ephPrivate),
    };

    // Initialize symmetric state with protocol name
    const protocolBytes = new TextEncoder().encode(PROTOCOL_NAME);
    let h: Uint8Array;
    if (protocolBytes.length <= 32) {
      h = new Uint8Array(32);
      h.set(protocolBytes);
    } else {
      h = sha256(protocolBytes);
    }

    this.symmetricState = {
      h: h,
      ck: new Uint8Array(h),
      k: null,
      n: 0n,
    };

    // MixHash(prologue) - empty for us
    this.mixHash(EMPTY);
  }

  /**
   * Get whether we're the initiator
   */
  get initiator(): boolean {
    return this.isInitiator;
  }

  /**
   * Write the next handshake message
   */
  writeMessage(payload: Uint8Array = EMPTY): Uint8Array {
    const parts: Uint8Array[] = [];

    if (this.isInitiator) {
      if (this.messageIndex === 0) {
        // -> e
        parts.push(this.localEphemeral.publicKey);
        this.mixHash(this.localEphemeral.publicKey);
        // Encrypt payload (no key yet, so it's plaintext)
        parts.push(this.encryptAndHash(payload));
      } else if (this.messageIndex === 2) {
        // -> s, se
        parts.push(this.encryptAndHash(this.localStatic.publicKey));
        this.mixKey(x25519DH(this.localStatic.privateKey, this.remoteEphemeral!));
        parts.push(this.encryptAndHash(payload));
      } else {
        throw new Error('Unexpected message index for initiator');
      }
    } else {
      if (this.messageIndex === 1) {
        // <- e, ee, s, es
        parts.push(this.localEphemeral.publicKey);
        this.mixHash(this.localEphemeral.publicKey);
        this.mixKey(x25519DH(this.localEphemeral.privateKey, this.remoteEphemeral!));
        parts.push(this.encryptAndHash(this.localStatic.publicKey));
        this.mixKey(x25519DH(this.localStatic.privateKey, this.remoteEphemeral!));
        parts.push(this.encryptAndHash(payload));
      } else {
        throw new Error('Unexpected message index for responder');
      }
    }

    this.messageIndex++;
    return concatBytes(...parts);
  }

  /**
   * Read and process a handshake message
   */
  readMessage(message: Uint8Array): Uint8Array {
    let offset = 0;

    if (this.isInitiator) {
      if (this.messageIndex === 1) {
        // <- e, ee, s, es
        this.remoteEphemeral = message.slice(offset, offset + 32);
        offset += 32;
        this.mixHash(this.remoteEphemeral);
        this.mixKey(x25519DH(this.localEphemeral.privateKey, this.remoteEphemeral));

        const encryptedStatic = message.slice(offset, offset + 32 + 16);
        offset += 32 + 16;
        this.remoteStatic = this.decryptAndHash(encryptedStatic);
        this.mixKey(x25519DH(this.localEphemeral.privateKey, this.remoteStatic));

        const encryptedPayload = message.slice(offset);
        const payload = this.decryptAndHash(encryptedPayload);
        this.messageIndex++;
        return payload;
      } else {
        throw new Error('Unexpected message index for initiator');
      }
    } else {
      if (this.messageIndex === 0) {
        // -> e
        this.remoteEphemeral = message.slice(offset, offset + 32);
        offset += 32;
        this.mixHash(this.remoteEphemeral);

        const encryptedPayload = message.slice(offset);
        const payload = this.decryptAndHash(encryptedPayload);
        this.messageIndex++;
        return payload;
      } else if (this.messageIndex === 2) {
        // -> s, se
        const encryptedStatic = message.slice(offset, offset + 32 + 16);
        offset += 32 + 16;
        this.remoteStatic = this.decryptAndHash(encryptedStatic);
        this.mixKey(x25519DH(this.localEphemeral.privateKey, this.remoteStatic));

        const encryptedPayload = message.slice(offset);
        const payload = this.decryptAndHash(encryptedPayload);
        this.messageIndex++;
        return payload;
      } else {
        throw new Error('Unexpected message index for responder');
      }
    }
  }

  /**
   * Check if handshake is complete
   */
  isComplete(): boolean {
    return this.messageIndex === 3;
  }

  /**
   * Split symmetric state into send/receive cipher states
   */
  finalize(): NoiseState {
    if (!this.isComplete()) {
      throw new Error('Handshake not complete');
    }

    if (!this.remoteStatic) {
      throw new Error('Remote static key not received');
    }

    // HKDF split for send/receive keys
    const output = hkdf(sha256, this.symmetricState.ck, EMPTY, EMPTY, 64);
    const k1 = output.slice(0, 32);
    const k2 = output.slice(32, 64);

    // Initiator sends with k1, receives with k2
    // Responder sends with k2, receives with k1
    const [sendKey, recvKey] = this.isInitiator ? [k1, k2] : [k2, k1];

    return {
      sendCipher: { key: sendKey, nonce: 0n },
      recvCipher: { key: recvKey, nonce: 0n },
      remoteStaticKey: this.remoteStatic,
      handshakeHash: new Uint8Array(this.symmetricState.h),
    };
  }

  /**
   * Get the handshake hash (for channel binding)
   */
  getHandshakeHash(): Uint8Array {
    return new Uint8Array(this.symmetricState.h);
  }

  private mixHash(data: Uint8Array): void {
    this.symmetricState.h = sha256(concatBytes(this.symmetricState.h, data));
  }

  private mixKey(inputKeyMaterial: Uint8Array): void {
    const output = hkdf(sha256, this.symmetricState.ck, EMPTY, inputKeyMaterial, 64);
    this.symmetricState.ck = output.slice(0, 32);
    this.symmetricState.k = output.slice(32, 64);
    this.symmetricState.n = 0n;
  }

  private encryptAndHash(plaintext: Uint8Array): Uint8Array {
    let ciphertext: Uint8Array;

    if (this.symmetricState.k === null) {
      // No key yet, return plaintext
      ciphertext = plaintext;
    } else {
      ciphertext = this.encrypt(plaintext);
    }

    this.mixHash(ciphertext);
    return ciphertext;
  }

  private decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    let plaintext: Uint8Array;

    if (this.symmetricState.k === null) {
      // No key yet, ciphertext is plaintext
      plaintext = ciphertext;
    } else {
      plaintext = this.decrypt(ciphertext);
    }

    this.mixHash(ciphertext);
    return plaintext;
  }

  private encrypt(plaintext: Uint8Array): Uint8Array {
    const nonce = this.nonceToBytes(this.symmetricState.n);
    this.symmetricState.n++;

    const cipher = chacha20poly1305(this.symmetricState.k!, nonce, this.symmetricState.h);
    return cipher.encrypt(plaintext);
  }

  private decrypt(ciphertext: Uint8Array): Uint8Array {
    const nonce = this.nonceToBytes(this.symmetricState.n);
    this.symmetricState.n++;

    const cipher = chacha20poly1305(this.symmetricState.k!, nonce, this.symmetricState.h);
    return cipher.decrypt(ciphertext);
  }

  private nonceToBytes(n: bigint): Uint8Array {
    const bytes = new Uint8Array(12);
    const view = new DataView(bytes.buffer);
    view.setBigUint64(4, n, true); // Little-endian, 4-byte padding
    return bytes;
  }
}

/**
 * Create an initiator handshake
 */
export function createInitiatorHandshake(
  localStaticPrivateKey: Uint8Array,
  localStaticPublicKey: Uint8Array
): NoiseHandshake {
  return new NoiseHandshake(localStaticPrivateKey, localStaticPublicKey, true);
}

/**
 * Create a responder handshake
 */
export function createResponderHandshake(
  localStaticPrivateKey: Uint8Array,
  localStaticPublicKey: Uint8Array
): NoiseHandshake {
  return new NoiseHandshake(localStaticPrivateKey, localStaticPublicKey, false);
}

/**
 * Encrypt data with established cipher state
 */
export function noiseEncrypt(
  state: NoiseCipherState,
  plaintext: Uint8Array,
  ad: Uint8Array = EMPTY
): Uint8Array {
  // Per R5/L1: Check for nonce overflow (defense-in-depth)
  if (state.nonce >= MAX_NONCE) {
    throw new Error('Nonce overflow: session must be rekeyed or terminated');
  }

  const nonce = nonceToBytes(state.nonce);
  state.nonce++;

  const cipher = chacha20poly1305(state.key, nonce, ad);
  return cipher.encrypt(plaintext);
}

/**
 * Decrypt data with established cipher state
 */
export function noiseDecrypt(
  state: NoiseCipherState,
  ciphertext: Uint8Array,
  ad: Uint8Array = EMPTY
): Uint8Array {
  // Per R5/L1: Check for nonce overflow (defense-in-depth)
  if (state.nonce >= MAX_NONCE) {
    throw new Error('Nonce overflow: session must be rekeyed or terminated');
  }

  const nonce = nonceToBytes(state.nonce);
  state.nonce++;

  const cipher = chacha20poly1305(state.key, nonce, ad);
  return cipher.decrypt(ciphertext);
}

function nonceToBytes(n: bigint): Uint8Array {
  const bytes = new Uint8Array(12);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(4, n, true);
  return bytes;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
