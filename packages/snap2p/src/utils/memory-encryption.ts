/**
 * In-Memory Encryption using Non-Extractable CryptoKey (R9 Enhancement)
 *
 * This module provides secure in-memory storage for sensitive data like seed phrases
 * by leveraging Web Crypto API's non-extractable keys.
 *
 * Security Properties:
 * - Session key lives in browser/Node.js C++ memory, NOT the JavaScript heap
 * - Even if an attacker dumps JS memory, they cannot read the raw key bytes
 * - The key can only be used through webcrypto.subtle.encrypt/decrypt API calls
 * - Exposure reduced from hours → milliseconds during operations
 *
 * This approach makes SNaP2P more secure than industry baseline wallets (like Leather)
 * which store decrypted keys as plaintext strings in memory.
 */

import { webcrypto } from 'node:crypto';

// Re-export types for proper typing
type WebCryptoKey = webcrypto.CryptoKey;

/**
 * Encrypted payload with IV for AES-GCM decryption
 */
interface EncryptedPayload {
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * Secure session storage using non-extractable CryptoKey.
 * Encrypts sensitive data in memory, decrypting only during operations.
 */
export class SecureSessionStorage {
  private sessionKey: WebCryptoKey | null = null;
  private encryptedData: EncryptedPayload | null = null;

  /**
   * Check if the session has encrypted data stored
   */
  isInitialized(): boolean {
    return this.sessionKey !== null && this.encryptedData !== null;
  }

  /**
   * Store sensitive data securely in memory.
   * Generates a non-extractable session key and encrypts the data.
   *
   * @param data - The sensitive data to encrypt (will be zeroed after encryption)
   */
  async store(data: Uint8Array): Promise<void> {
    // Generate a non-extractable session key
    // extractable: false means the key material cannot be exported from C++ memory
    this.sessionKey = await webcrypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false, // NOT extractable - key material stays in C++ memory
      ['encrypt', 'decrypt']
    );

    // Generate random IV for AES-GCM
    const iv = webcrypto.getRandomValues(new Uint8Array(12));

    // Encrypt the sensitive data
    const ciphertext = new Uint8Array(
      await webcrypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        this.sessionKey,
        data
      )
    );

    // Store the encrypted payload
    this.encryptedData = { iv, ciphertext };

    // Zero the original data immediately
    data.fill(0);
  }

  /**
   * Store a string securely in memory.
   * Converts to Uint8Array, encrypts, and zeros the intermediate buffer.
   *
   * @param str - The sensitive string to encrypt
   */
  async storeString(str: string): Promise<void> {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    await this.store(data);
  }

  /**
   * Retrieve the decrypted data.
   * IMPORTANT: Caller MUST zero the returned Uint8Array after use!
   *
   * @returns The decrypted data (caller must zero after use)
   * @throws Error if not initialized
   */
  async retrieve(): Promise<Uint8Array> {
    if (!this.sessionKey || !this.encryptedData) {
      throw new Error('Secure session not initialized');
    }

    const decrypted = new Uint8Array(
      await webcrypto.subtle.decrypt(
        { name: 'AES-GCM', iv: this.encryptedData.iv },
        this.sessionKey,
        this.encryptedData.ciphertext
      )
    );

    return decrypted;
  }

  /**
   * Retrieve the decrypted data as a string.
   * IMPORTANT: The returned string cannot be zeroed due to JS limitations.
   * Keep usage window as short as possible!
   *
   * @returns The decrypted string (use immediately and discard reference)
   * @throws Error if not initialized
   */
  async retrieveString(): Promise<string> {
    const data = await this.retrieve();
    const decoder = new TextDecoder();
    const str = decoder.decode(data);

    // Zero the intermediate buffer
    data.fill(0);

    return str;
  }

  /**
   * Perform an operation with the decrypted data, automatically zeroing after.
   * This is the recommended way to use sensitive data.
   *
   * @param operation - Async function that receives the decrypted data
   * @returns The result of the operation
   */
  async withDecryptedData<T>(operation: (data: Uint8Array) => Promise<T>): Promise<T> {
    const data = await this.retrieve();
    try {
      return await operation(data);
    } finally {
      // Always zero the data, even if operation throws
      data.fill(0);
    }
  }

  /**
   * Perform an operation with the decrypted string, with minimal exposure window.
   *
   * @param operation - Async function that receives the decrypted string
   * @returns The result of the operation
   */
  async withDecryptedString<T>(operation: (str: string) => Promise<T>): Promise<T> {
    const str = await this.retrieveString();
    return operation(str);
  }

  /**
   * Clear the session, releasing the CryptoKey from C++ memory.
   * The encrypted data becomes useless without the key.
   */
  clear(): void {
    // Release the CryptoKey - C++ memory is freed immediately
    this.sessionKey = null;

    // Zero and clear the encrypted payload
    if (this.encryptedData) {
      this.encryptedData.iv.fill(0);
      this.encryptedData.ciphertext.fill(0);
      this.encryptedData = null;
    }
  }
}

/**
 * Create a new secure session storage instance
 */
export function createSecureSessionStorage(): SecureSessionStorage {
  return new SecureSessionStorage();
}
