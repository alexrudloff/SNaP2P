/**
 * Cryptographic primitives for SNaP2P
 */

export type { NodeKeyPair } from './keys.js';
export {
  generateNodeKeyPair,
  createNodeKeyPair,
  sign,
  verify,
  x25519DH,
  getRandomBytes,
  publicKeyToHex,
  publicKeyFromHex,
  constantTimeEqual,
  ed25519PublicKeyToX25519,
} from './keys.js';

export type { NoiseState, NoiseCipherState } from './noise.js';
export {
  NoiseHandshake,
  createInitiatorHandshake,
  createResponderHandshake,
  noiseEncrypt,
  noiseDecrypt,
} from './noise.js';
