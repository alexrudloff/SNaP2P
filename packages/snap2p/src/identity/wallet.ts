/**
 * Wallet interface for SNaP2P identity.
 *
 * This module defines the wallet interface that SNaP2P requires for signing
 * attestations. It can be implemented by:
 * - The built-in generated wallet (for demos/testing)
 * - External wallet providers (like hula's StacksWalletIdentityProvider)
 *
 * Per SPECS.md Section 2.2, this is the "Wallet key" - the Stacks principal
 * keypair used to sign attestations. It is separate from the "Node key" used
 * for transport encryption.
 */

import {
  privateKeyToPublic,
  signMessageHashRsv,
  publicKeyToAddress,
  AddressVersion,
  publicKeyFromSignatureRsv,
} from '@stacks/transactions';
import { sha256 } from '@noble/hashes/sha256';
import { Principal, createPrincipal } from '../types/principal.js';
import { bytesToHex, hexToBytes } from '../utils/hex.js';

/**
 * Core wallet interface required by SNaP2P.
 *
 * Any wallet implementation must provide these methods to work with SNaP2P.
 * This interface is intentionally minimal to allow easy integration with
 * external wallet providers.
 */
export interface WalletProvider {
  /** Get the Stacks address */
  getAddress(): string;

  /**
   * Sign a message and return the signature.
   * The message will be hashed before signing if not already hashed.
   * Returns the signature as bytes.
   */
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/**
 * Extended wallet interface with additional metadata.
 * Used internally by SNaP2P for convenience.
 */
export interface Wallet extends WalletProvider {
  /** The wallet's principal (stacks:<address>) */
  readonly principal: Principal;
  /** The wallet's Stacks address (convenience, same as getAddress()) */
  readonly address: string;
}

/**
 * Options for creating a wallet
 */
export interface WalletOptions {
  /** Use testnet addresses */
  testnet?: boolean;
}

/**
 * Wrap a WalletProvider into a full Wallet interface.
 * Use this to adapt external wallet providers (like hula's IIdentityProvider)
 * to work with SNaP2P.
 */
export function wrapWalletProvider(provider: WalletProvider): Wallet {
  const address = provider.getAddress();
  const principal = createPrincipal(address);

  return {
    principal,
    address,
    getAddress: () => address,
    sign: (message: Uint8Array) => provider.sign(message),
  };
}

/**
 * Create a wallet from a Stacks private key.
 *
 * This creates a fully functional wallet that can sign attestations.
 * For production use, consider using an external wallet provider
 * that handles key storage securely.
 */
export function createWallet(privateKeyHex: string, options: WalletOptions = {}): Wallet {
  const publicKey = privateKeyToPublic(privateKeyHex);

  const addressVersion = options.testnet
    ? AddressVersion.TestnetSingleSig
    : AddressVersion.MainnetSingleSig;

  const address = publicKeyToAddress(addressVersion, publicKey);
  const principal = createPrincipal(address);

  return {
    principal,
    address,
    getAddress: () => address,
    async sign(message: Uint8Array): Promise<Uint8Array> {
      // Hash the message (standard practice for signing)
      const messageHash = sha256(message);
      const signature = signMessageHashRsv({
        privateKey: privateKeyHex,
        messageHash: Buffer.from(messageHash).toString('hex'),
      });
      return hexToBytes(signature);
    },
  };
}

/**
 * Generate a new random wallet.
 *
 * WARNING: This generates an ephemeral wallet that will be lost when the
 * process exits. For persistent wallets, use an external wallet provider
 * or store the returned privateKey securely.
 */
export function generateWallet(options: WalletOptions = {}): { wallet: Wallet; privateKey: string } {
  // Generate 32 random bytes for private key
  const privateKeyBytes = new Uint8Array(32);
  crypto.getRandomValues(privateKeyBytes);

  // Convert to hex (compressed format with 01 suffix)
  const privateKeyHex = bytesToHex(privateKeyBytes) + '01';
  const wallet = createWallet(privateKeyHex, options);

  return { wallet, privateKey: privateKeyHex };
}

/**
 * Verify a wallet signature using secp256k1 recovery.
 * Recovers the public key from the signature and verifies it matches.
 */
export function verifyWalletSignature(
  expectedPublicKeyHex: string,
  message: Uint8Array,
  signature: Uint8Array
): boolean {
  try {
    // Hash the message (same as signing)
    const messageHash = sha256(message);
    const messageHashHex = Buffer.from(messageHash).toString('hex');

    // Convert signature to hex format expected by Stacks library
    const signatureHex = bytesToHex(signature);

    // Recover the public key from the RSV signature
    // publicKeyFromSignatureRsv expects (messageHash: string, signature: string)
    const recoveredPublicKey = publicKeyFromSignatureRsv(messageHashHex, signatureHex);

    // Compare recovered public key with expected (case-insensitive)
    return recoveredPublicKey.toLowerCase() === expectedPublicKeyHex.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Get the Stacks address from a public key.
 */
export function addressFromPublicKey(publicKeyHex: string, options: WalletOptions = {}): string {
  const addressVersion = options.testnet
    ? AddressVersion.TestnetSingleSig
    : AddressVersion.MainnetSingleSig;

  return publicKeyToAddress(addressVersion, publicKeyHex);
}

// hexToBytes and bytesToHex are imported from '../utils/hex.js'
