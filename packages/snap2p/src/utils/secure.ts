/**
 * Secure memory utilities for handling sensitive data.
 *
 * Note: JavaScript/Node.js doesn't provide true secure memory allocation,
 * but we can at least overwrite sensitive data when we're done with it
 * to reduce the window of exposure.
 */

/**
 * Securely zero out a Uint8Array by overwriting its contents.
 * This helps reduce the window of exposure for sensitive data in memory.
 */
export function secureZero(buffer: Uint8Array): void {
  buffer.fill(0);
}

/**
 * Securely zero out a string by creating a mutable buffer representation.
 * Note: Due to JavaScript string immutability, the original string may still
 * exist in memory until garbage collected. This function helps encourage
 * the pattern of working with mutable buffers for sensitive data.
 *
 * @returns An empty string to assign back to the variable
 */
export function secureZeroString(_str: string): string {
  // In JavaScript, strings are immutable, so we can't actually zero the original.
  // Best practice is to work with Uint8Array for sensitive data.
  // This function serves as documentation and returns empty string for reassignment.
  return '';
}

/**
 * Create a sensitive data container that tracks whether data has been cleared.
 * Use this for sensitive strings that need to be securely handled.
 */
export class SensitiveData {
  private data: Uint8Array | null;
  private cleared = false;

  constructor(data: string | Uint8Array) {
    if (typeof data === 'string') {
      this.data = new TextEncoder().encode(data);
    } else {
      this.data = new Uint8Array(data);
    }
  }

  /**
   * Get the data as a string.
   * @throws Error if data has been cleared
   */
  toString(): string {
    if (this.cleared || !this.data) {
      throw new Error('Sensitive data has been cleared');
    }
    return new TextDecoder().decode(this.data);
  }

  /**
   * Get the data as bytes.
   * @throws Error if data has been cleared
   */
  toBytes(): Uint8Array {
    if (this.cleared || !this.data) {
      throw new Error('Sensitive data has been cleared');
    }
    return new Uint8Array(this.data);
  }

  /**
   * Clear the sensitive data from memory.
   */
  clear(): void {
    if (this.data) {
      secureZero(this.data);
      this.data = null;
    }
    this.cleared = true;
  }

  /**
   * Check if the data has been cleared.
   */
  isCleared(): boolean {
    return this.cleared;
  }
}
