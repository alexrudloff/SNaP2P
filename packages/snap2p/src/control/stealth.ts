/**
 * Stealth mode support for SNaP2P.
 * Per SPECS 4.3: Stealth handshake ordering with KNOCK/KNOCK_RESPONSE.
 *
 * Goal: Avoid leaking alias/meta and avoid expensive work for scanners.
 */

import {
  MessageType,
  KnockMessage,
  KnockResponseMessage,
  AuthFailMessage,
} from '../types/messages.js';
import { ErrorCode } from '../types/errors.js';
import { getRandomBytes, constantTimeEqual } from '../crypto/keys.js';

/**
 * Invite token configuration
 */
export interface InviteTokenConfig {
  /** Token expiry time in milliseconds (default: 24 hours) */
  expiryMs?: number;
  /** Maximum uses per token (default: unlimited) */
  maxUses?: number;
  /** Whether tokens are single-use (default: false per SPECS 4.2.2) */
  singleUse?: boolean;
}

/**
 * Stored invite token with metadata
 */
interface StoredToken {
  token: Uint8Array;
  createdAt: number;
  expiresAt: number;
  useCount: number;
  maxUses: number | null;
  singleUse: boolean;
}

/**
 * Manages invite tokens for Stealth mode.
 * Per SPECS 4.2: Invite Tokens are shared out-of-band along with Locator.
 */
export class InviteTokenManager {
  private tokens: Map<string, StoredToken> = new Map();
  private config: Required<InviteTokenConfig>;
  private cleanupTimer: NodeJS.Timeout | null = null;

  constructor(config: InviteTokenConfig = {}) {
    this.config = {
      expiryMs: config.expiryMs ?? 24 * 60 * 60 * 1000, // 24 hours
      maxUses: config.maxUses ?? 0, // 0 = unlimited
      singleUse: config.singleUse ?? false,
    };

    // Periodic cleanup of expired tokens
    this.startCleanup();
  }

  /**
   * Generate a new invite token.
   * Per SPECS 4.2.1: Opaque token is 128-256 bits (16-32 bytes).
   */
  generateToken(options?: { expiryMs?: number; maxUses?: number; singleUse?: boolean }): Uint8Array {
    const token = getRandomBytes(32); // 256 bits
    const now = Date.now();

    const stored: StoredToken = {
      token: new Uint8Array(token),
      createdAt: now,
      expiresAt: now + (options?.expiryMs ?? this.config.expiryMs),
      useCount: 0,
      maxUses: options?.maxUses ?? (this.config.maxUses || null),
      singleUse: options?.singleUse ?? this.config.singleUse,
    };

    this.tokens.set(this.tokenToKey(token), stored);
    return token;
  }

  /**
   * Add an existing token (for tokens generated elsewhere).
   */
  addToken(token: Uint8Array, options?: { expiryMs?: number; maxUses?: number; singleUse?: boolean }): void {
    if (token.length < 16 || token.length > 32) {
      throw new Error('Token must be 16-32 bytes per SPECS 4.2.1');
    }

    const now = Date.now();
    const stored: StoredToken = {
      token: new Uint8Array(token),
      createdAt: now,
      expiresAt: now + (options?.expiryMs ?? this.config.expiryMs),
      useCount: 0,
      maxUses: options?.maxUses ?? (this.config.maxUses || null),
      singleUse: options?.singleUse ?? this.config.singleUse,
    };

    this.tokens.set(this.tokenToKey(token), stored);
  }

  /**
   * Validate an invite token.
   * Returns true if valid, false otherwise.
   * If valid and not single-use, increments use count.
   */
  validateToken(token: Uint8Array): boolean {
    // Find matching token using constant-time comparison
    for (const [key, stored] of this.tokens.entries()) {
      if (constantTimeEqual(token, stored.token)) {
        // Check expiry
        if (Date.now() > stored.expiresAt) {
          this.tokens.delete(key);
          return false;
        }

        // Check max uses
        if (stored.maxUses !== null && stored.useCount >= stored.maxUses) {
          return false;
        }

        // Valid - increment use count
        stored.useCount++;

        // Remove if single-use
        if (stored.singleUse) {
          this.tokens.delete(key);
        }

        return true;
      }
    }

    return false;
  }

  /**
   * Revoke an invite token.
   */
  revokeToken(token: Uint8Array): boolean {
    const key = this.tokenToKey(token);
    return this.tokens.delete(key);
  }

  /**
   * Get the number of active tokens.
   */
  getActiveTokenCount(): number {
    return this.tokens.size;
  }

  /**
   * Clear all tokens.
   */
  clearAll(): void {
    this.tokens.clear();
  }

  /**
   * Stop the token manager and clean up resources.
   */
  stop(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.tokens.clear();
  }

  private tokenToKey(token: Uint8Array): string {
    return Array.from(token).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private startCleanup(): void {
    // Cleanup every hour
    this.cleanupTimer = setInterval(() => {
      const now = Date.now();
      for (const [key, stored] of this.tokens.entries()) {
        if (now > stored.expiresAt) {
          this.tokens.delete(key);
        }
      }
    }, 60 * 60 * 1000);

    this.cleanupTimer.unref();
  }
}

/**
 * Create a KNOCK message.
 * Per SPECS 4.3 Step 1: Client sends KNOCK immediately after TCP connect.
 */
export function createKnockMessage(inviteToken: Uint8Array): KnockMessage {
  return {
    type: MessageType.KNOCK,
    inviteToken,
  };
}

/**
 * Create a KNOCK_RESPONSE message.
 */
export function createKnockResponseMessage(allowed: boolean): KnockResponseMessage {
  return {
    type: MessageType.KNOCK_RESPONSE,
    allowed,
  };
}

/**
 * Create an AUTH_FAIL message for invalid invite token.
 * Per SPECS 4.3 Step 1: "If invite token is missing/invalid: respond AUTH_FAIL{ERR_INVITE_INVALID}"
 */
export function createInviteFailMessage(reason?: string): AuthFailMessage {
  return {
    type: MessageType.AUTH_FAIL,
    errorCode: ErrorCode.ERR_INVALID_TOKEN,
    reason: reason ?? 'Invalid or expired invite token',
  };
}

/**
 * Create an AUTH_FAIL message for missing invite token in Stealth mode.
 */
export function createInviteRequiredMessage(): AuthFailMessage {
  return {
    type: MessageType.AUTH_FAIL,
    errorCode: ErrorCode.ERR_INVITE_REQUIRED,
    reason: 'Invite token required for stealth mode',
  };
}
