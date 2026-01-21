/**
 * Ed25519 key management for SNaP2P node identity.
 * Ed25519 keys are used for signing and converted to X25519 for Noise DH.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { x25519 } from '@noble/curves/ed25519';
import { edwardsToMontgomeryPub } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { bytesToHex, hexToBytes } from '../utils/hex.js';

/**
 * A node keypair with both Ed25519 (signing) and X25519 (DH) components
 */
export interface NodeKeyPair {
  /** Ed25519 private key (32 bytes) */
  readonly privateKey: Uint8Array;
  /** Ed25519 public key (32 bytes) */
  readonly publicKey: Uint8Array;
  /** X25519 private key derived from Ed25519 (for Noise DH) */
  readonly x25519PrivateKey: Uint8Array;
  /** X25519 public key derived from Ed25519 (for Noise DH) */
  readonly x25519PublicKey: Uint8Array;
}

/**
 * Generate a new random Ed25519 keypair
 */
export function generateNodeKeyPair(): NodeKeyPair {
  const privateKey = randomBytes(32);
  return createNodeKeyPair(privateKey);
}

/**
 * Create a keypair from an existing private key
 */
export function createNodeKeyPair(privateKey: Uint8Array): NodeKeyPair {
  if (privateKey.length !== 32) {
    throw new Error('Private key must be 32 bytes');
  }

  const publicKey = ed25519.getPublicKey(privateKey);

  // Convert Ed25519 keys to X25519 for Noise DH
  // Per RFC 8032 and libsodium, we hash the private key and take first 32 bytes
  const hash = sha512(privateKey);
  const x25519PrivateKey = hash.slice(0, 32);
  // Clamp the scalar as per X25519 spec
  x25519PrivateKey[0] &= 248;
  x25519PrivateKey[31] &= 127;
  x25519PrivateKey[31] |= 64;

  const x25519PublicKey = x25519.getPublicKey(x25519PrivateKey);

  return {
    privateKey: new Uint8Array(privateKey),
    publicKey,
    x25519PrivateKey,
    x25519PublicKey,
  };
}

/**
 * Sign data with Ed25519 private key
 */
export function sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey);
}

/**
 * Verify Ed25519 signature
 */
export function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Perform X25519 Diffie-Hellman
 */
export function x25519DH(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

/**
 * Generate random bytes
 */
export function getRandomBytes(length: number): Uint8Array {
  return randomBytes(length);
}

/**
 * Encode public key to hex string
 */
export function publicKeyToHex(publicKey: Uint8Array): string {
  return bytesToHex(publicKey);
}

/**
 * Decode public key from hex string
 */
export function publicKeyFromHex(hex: string): Uint8Array {
  if (hex.length !== 64) {
    throw new Error('Invalid public key hex: expected 64 characters');
  }
  return hexToBytes(hex);
}

/**
 * Compare two byte arrays for equality in constant time
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Convert an Ed25519 public key to its corresponding X25519 public key.
 * This is used to verify that an attestation's node public key (Ed25519)
 * corresponds to the Noise handshake's static key (X25519).
 *
 * Per SPECS 2.4: "The secure channel handshake MUST be cryptographically
 * bound to node_pubkey"
 */
export function ed25519PublicKeyToX25519(ed25519PublicKey: Uint8Array): Uint8Array {
  if (ed25519PublicKey.length !== 32) {
    throw new Error('Ed25519 public key must be 32 bytes');
  }
  return edwardsToMontgomeryPub(ed25519PublicKey);
}
