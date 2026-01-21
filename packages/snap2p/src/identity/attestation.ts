/**
 * NodeKeyAttestation v1 implementation.
 * Binds a Stacks principal to an Ed25519 node public key.
 *
 * The attestation is signed by the wallet key and verifiable by anyone
 * with knowledge of the wallet's public key (derivable from the Stacks address).
 */

import { encode, decode } from '../wire/codec.js';
import { sha256 } from '@noble/hashes/sha256';
import { Principal, formatPrincipal, parsePrincipal } from '../types/principal.js';
import { Wallet } from './wallet.js';
import { publicKeyToHex, publicKeyFromHex } from '../crypto/keys.js';

/**
 * NodeKeyAttestation v1 structure
 */
export interface NodeKeyAttestation {
  /** Attestation version (1) */
  readonly version: 1;
  /** The Stacks principal being attested */
  readonly principal: Principal;
  /** Ed25519 node public key (32 bytes) */
  readonly nodePublicKey: Uint8Array;
  /** Timestamp when attestation was created (ms since epoch) */
  readonly timestamp: bigint;
  /** Timestamp when attestation expires (ms since epoch) */
  readonly expiresAt: bigint;
  /** Wallet signature over the canonical CBOR encoding */
  readonly signature: Uint8Array;
}

/**
 * Canonical wire format for attestation (for signing)
 */
interface AttestationPayload {
  v: number;
  p: string;
  npk: string;
  ts: bigint;
  exp: bigint;
}

/** Clock skew tolerance: ±5 minutes in milliseconds */
const CLOCK_SKEW_TOLERANCE = 5 * 60 * 1000;

/** Default attestation validity: 24 hours */
const DEFAULT_VALIDITY_MS = 24 * 60 * 60 * 1000;

/**
 * Create a new NodeKeyAttestation
 */
export async function createAttestation(
  wallet: Wallet,
  nodePublicKey: Uint8Array,
  options?: { validityMs?: number }
): Promise<NodeKeyAttestation> {
  const now = BigInt(Date.now());
  const validityMs = options?.validityMs ?? DEFAULT_VALIDITY_MS;
  const expiresAt = now + BigInt(validityMs);

  // Create the payload for signing (canonical CBOR)
  const payload: AttestationPayload = {
    v: 1,
    p: formatPrincipal(wallet.principal),
    npk: publicKeyToHex(nodePublicKey),
    ts: now,
    exp: expiresAt,
  };

  const payloadBytes = encode(payload);
  const signature = await wallet.sign(payloadBytes);

  return {
    version: 1,
    principal: wallet.principal,
    nodePublicKey: new Uint8Array(nodePublicKey),
    timestamp: now,
    expiresAt,
    signature,
  };
}

/**
 * Serialize an attestation to bytes
 */
export function serializeAttestation(attestation: NodeKeyAttestation): Uint8Array {
  const wire = {
    v: attestation.version,
    p: formatPrincipal(attestation.principal),
    npk: publicKeyToHex(attestation.nodePublicKey),
    ts: attestation.timestamp,
    exp: attestation.expiresAt,
    sig: attestation.signature,
  };
  return encode(wire);
}

/**
 * Deserialize an attestation from bytes
 */
export function deserializeAttestation(data: Uint8Array): NodeKeyAttestation {
  const wire = decode<{
    v: number;
    p: string;
    npk: string;
    ts: bigint;
    exp: bigint;
    sig: Uint8Array;
  }>(data);

  if (wire.v !== 1) {
    throw new Error(`Unsupported attestation version: ${wire.v}`);
  }

  return {
    version: 1,
    principal: parsePrincipal(wire.p),
    nodePublicKey: publicKeyFromHex(wire.npk),
    timestamp: wire.ts,
    expiresAt: wire.exp,
    signature: wire.sig,
  };
}

/**
 * Result of attestation verification
 */
export interface VerificationResult {
  /** Whether the attestation is valid */
  valid: boolean;
  /** Error message if invalid */
  error?: string;
  /** The principal if valid */
  principal?: Principal;
}

/**
 * Verify an attestation's structure and timestamps
 * Note: Full signature verification requires the wallet's public key
 */
export function verifyAttestation(attestation: NodeKeyAttestation): VerificationResult {
  const now = BigInt(Date.now());

  // Check version
  if (attestation.version !== 1) {
    return { valid: false, error: `Unsupported version: ${attestation.version}` };
  }

  // Check timestamp is not too far in the future (clock skew)
  const maxFutureTime = now + BigInt(CLOCK_SKEW_TOLERANCE);
  if (attestation.timestamp > maxFutureTime) {
    return { valid: false, error: 'Attestation timestamp is in the future' };
  }

  // Check expiration
  if (attestation.expiresAt <= now) {
    return { valid: false, error: 'Attestation has expired' };
  }

  // Check node public key length
  if (attestation.nodePublicKey.length !== 32) {
    return { valid: false, error: 'Invalid node public key length' };
  }

  // Check signature exists
  if (!attestation.signature || attestation.signature.length === 0) {
    return { valid: false, error: 'Missing signature' };
  }

  return { valid: true, principal: attestation.principal };
}

/**
 * Get the payload bytes for signature verification
 */
export function getAttestationPayloadBytes(attestation: NodeKeyAttestation): Uint8Array {
  const payload: AttestationPayload = {
    v: attestation.version,
    p: formatPrincipal(attestation.principal),
    npk: publicKeyToHex(attestation.nodePublicKey),
    ts: attestation.timestamp,
    exp: attestation.expiresAt,
  };
  return encode(payload);
}

/**
 * Check if an attestation is expired or will expire soon
 */
export function isAttestationExpiringSoon(
  attestation: NodeKeyAttestation,
  thresholdMs: number = 60 * 60 * 1000 // 1 hour
): boolean {
  const now = BigInt(Date.now());
  const threshold = now + BigInt(thresholdMs);
  return attestation.expiresAt <= threshold;
}
