/**
 * Identity management for SNaP2P
 */

export type { WalletProvider, Wallet, WalletOptions } from './wallet.js';
export {
  wrapWalletProvider,
  createWallet,
  generateWallet,
  verifyWalletSignature,
  addressFromPublicKey,
} from './wallet.js';

export type { WalletAccount, WalletManagerOptions } from './wallet-manager.js';
export { WalletManager } from './wallet-manager.js';

export type { NodeKeyAttestation, VerificationResult } from './attestation.js';
export {
  createAttestation,
  serializeAttestation,
  deserializeAttestation,
  verifyAttestation,
  verifyAttestationSignature,
  getAttestationPayloadBytes,
  isAttestationExpiringSoon,
} from './attestation.js';
