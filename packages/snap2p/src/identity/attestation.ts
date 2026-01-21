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
import { Wallet, addressFromPublicKey } from './wallet.js';
import { publicKeyToHex, publicKeyFromHex, getRandomBytes } from '../crypto/keys.js';
import { publicKeyFromSignatureRsv } from '@stacks/transactions';

/** Domain string for attestation signatures per SPECS 2.3.1 */
const ATTESTATION_DOMAIN = 'snap2p-nodekey-attestation-v1';

/**
 * NodeKeyAttestation v1 structure
 * Per SPECS 2.3.1
 */
export interface NodeKeyAttestation {
  /** Attestation version (1) */
  readonly version: 1;
  /** The Stacks principal being attested */
  readonly principal: Principal;
  /** Ed25519 node public key (32 bytes) */
  readonly nodePublicKey: Uint8Array;
  /** Timestamp when attestation was created (Unix seconds) */
  readonly timestamp: bigint;
  /** Timestamp when attestation expires (Unix seconds) */
  readonly expiresAt: bigint;
  /** Random nonce (16-32 bytes) per SPECS 2.3.1 */
  readonly nonce: Uint8Array;
  /** Domain string for signature binding per SPECS 2.3.1 */
  readonly domain: string;
  /** Wallet signature over the canonical CBOR encoding */
  readonly signature: Uint8Array;
}

/**
 * Canonical wire format for attestation (for signing)
 * Per SPECS 2.3.1 - includes all fields except sig
 */
interface AttestationPayload {
  v: number;
  p: string;
  npk: string;
  ts: bigint;
  exp: bigint;
  nonce: Uint8Array;
  domain: string;
}

/** Clock skew tolerance: ±5 minutes in seconds per SPECS 2.6 */
const CLOCK_SKEW_TOLERANCE_SECONDS = 5 * 60;

/** Default attestation validity: 24 hours in seconds */
const DEFAULT_VALIDITY_SECONDS = 24 * 60 * 60;

/** Nonce size in bytes (using 32 bytes for maximum security) */
const NONCE_SIZE = 32;

/**
 * Create a new NodeKeyAttestation
 * Per SPECS 2.3.1 - timestamps are Unix seconds
 */
export async function createAttestation(
  wallet: Wallet,
  nodePublicKey: Uint8Array,
  options?: { validitySeconds?: number }
): Promise<NodeKeyAttestation> {
  // Use Unix seconds per SPECS 3.0
  const now = BigInt(Math.floor(Date.now() / 1000));
  const validitySeconds = options?.validitySeconds ?? DEFAULT_VALIDITY_SECONDS;
  const expiresAt = now + BigInt(validitySeconds);

  // Generate random nonce per SPECS 2.3.1
  const nonce = getRandomBytes(NONCE_SIZE);

  // Create the payload for signing (canonical CBOR)
  // Includes all fields except sig per SPECS 2.3.1
  const payload: AttestationPayload = {
    v: 1,
    p: formatPrincipal(wallet.principal),
    npk: publicKeyToHex(nodePublicKey),
    ts: now,
    exp: expiresAt,
    nonce,
    domain: ATTESTATION_DOMAIN,
  };

  const payloadBytes = encode(payload);
  const signature = await wallet.sign(payloadBytes);

  return {
    version: 1,
    principal: wallet.principal,
    nodePublicKey: new Uint8Array(nodePublicKey),
    timestamp: now,
    expiresAt,
    nonce,
    domain: ATTESTATION_DOMAIN,
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
    nonce: attestation.nonce,
    domain: attestation.domain,
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
    nonce: Uint8Array;
    domain: string;
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
    nonce: wire.nonce,
    domain: wire.domain,
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
 * Per SPECS 2.3.1 and 2.6 (clock skew ±5 minutes)
 * Note: Full signature verification requires the wallet's public key
 */
export function verifyAttestation(attestation: NodeKeyAttestation): VerificationResult {
  // Use Unix seconds per SPECS 3.0
  const now = BigInt(Math.floor(Date.now() / 1000));

  // Check version
  if (attestation.version !== 1) {
    return { valid: false, error: `Unsupported version: ${attestation.version}` };
  }

  // Check domain per SPECS 2.3.1
  if (attestation.domain !== ATTESTATION_DOMAIN) {
    return { valid: false, error: `Invalid domain: expected ${ATTESTATION_DOMAIN}` };
  }

  // Check nonce length per SPECS 2.3.1 (16-32 bytes)
  if (!attestation.nonce || attestation.nonce.length < 16 || attestation.nonce.length > 32) {
    return { valid: false, error: 'Invalid nonce: must be 16-32 bytes' };
  }

  // Check timestamp is not too far in the future (clock skew per SPECS 2.6)
  const maxFutureTime = now + BigInt(CLOCK_SKEW_TOLERANCE_SECONDS);
  if (attestation.timestamp > maxFutureTime) {
    return { valid: false, error: 'Attestation timestamp is in the future' };
  }

  // Check expiration (with clock skew tolerance)
  const minExpireTime = now - BigInt(CLOCK_SKEW_TOLERANCE_SECONDS);
  if (attestation.expiresAt <= minExpireTime) {
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
 * Per SPECS 2.3.1 - includes all fields except sig
 */
export function getAttestationPayloadBytes(attestation: NodeKeyAttestation): Uint8Array {
  const payload: AttestationPayload = {
    v: attestation.version,
    p: formatPrincipal(attestation.principal),
    npk: publicKeyToHex(attestation.nodePublicKey),
    ts: attestation.timestamp,
    exp: attestation.expiresAt,
    nonce: attestation.nonce,
    domain: attestation.domain,
  };
  return encode(payload);
}

/**
 * Check if an attestation is expired or will expire soon
 * @param thresholdSeconds - threshold in seconds (default 1 hour)
 */
export function isAttestationExpiringSoon(
  attestation: NodeKeyAttestation,
  thresholdSeconds: number = 60 * 60 // 1 hour in seconds
): boolean {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const threshold = now + BigInt(thresholdSeconds);
  return attestation.expiresAt <= threshold;
}

/**
 * Verify an attestation with full cryptographic signature verification.
 * Per SPECS 2.3.1:
 * - Verify wallet signature
 * - Verify that recovered/derived address from the wallet public key matches principal
 *
 * @param attestation - The attestation to verify
 * @param options - Verification options (testnet flag)
 */
export function verifyAttestationSignature(
  attestation: NodeKeyAttestation,
  options?: { testnet?: boolean }
): VerificationResult {
  // First do structural verification
  const structuralResult = verifyAttestation(attestation);
  if (!structuralResult.valid) {
    return structuralResult;
  }

  try {
    // Get the payload bytes that were signed
    const payloadBytes = getAttestationPayloadBytes(attestation);

    // Hash the payload (same as signing)
    const messageHash = sha256(payloadBytes);
    const messageHashHex = Buffer.from(messageHash).toString('hex');

    // Convert signature to hex
    const signatureHex = Array.from(attestation.signature)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // Recover the public key from the RSV signature
    // publicKeyFromSignatureRsv expects (messageHash: string, signature: string)
    const recoveredPublicKey = publicKeyFromSignatureRsv(messageHashHex, signatureHex);

    // Derive the address from the recovered public key
    const derivedAddress = addressFromPublicKey(recoveredPublicKey, options);

    // Compare with the attestation's principal address
    if (derivedAddress !== attestation.principal.address) {
      return {
        valid: false,
        error: `Signature verification failed: recovered address ${derivedAddress} does not match principal ${attestation.principal.address}`,
      };
    }

    return { valid: true, principal: attestation.principal };
  } catch (err) {
    return {
      valid: false,
      error: `Signature verification failed: ${err instanceof Error ? err.message : 'unknown error'}`,
    };
  }
}
