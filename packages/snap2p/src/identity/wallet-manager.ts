/**
 * Wallet Manager for SNaP2P
 *
 * Handles wallet creation, storage, and signing with proper encryption.
 * Based on patterns from hula's wallet implementation.
 *
 * Features:
 * - BIP39 seed phrase generation/restoration
 * - AES-256-GCM encrypted storage with scrypt KDF
 * - Proper Stacks secp256k1 signing
 * - Multi-account support
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  generateSecretKey,
  generateWallet as generateStacksWallet,
} from '@stacks/wallet-sdk';
import {
  getAddressFromPrivateKey,
  signMessageHashRsv,
} from '@stacks/transactions';
import { sha256 } from '@noble/hashes/sha256';
import { Principal, createPrincipal } from '../types/principal.js';
import { Wallet } from './wallet.js';

/** Wallet file format version */
const WALLET_FILE_VERSION = 1;

/** Default directory for wallet storage */
const DEFAULT_WALLET_DIR = path.join(os.homedir(), '.snap2p', 'wallets');

/** Scrypt parameters */
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 32;

/**
 * Encrypted wallet file structure
 */
interface WalletFile {
  version: number;
  network: 'mainnet' | 'testnet';
  address: string;
  displayName: string;
  createdAt: string;
  crypto: {
    salt: string;      // base64
    iv: string;        // base64
    tag: string;       // base64
    ciphertext: string; // base64 encrypted seed phrase
    kdf: 'scrypt';
  };
}

/**
 * Account metadata stored in registry
 */
export interface WalletAccount {
  id: string;
  address: string;
  displayName: string;
  createdAt: string;
  lastUsed: string;
}

/**
 * Registry file structure
 */
interface WalletRegistry {
  version: number;
  accounts: WalletAccount[];
  currentAccountId: string | null;
}

/**
 * Options for wallet manager
 */
export interface WalletManagerOptions {
  /** Directory for wallet storage (default: ~/.snap2p/wallets) */
  walletDir?: string;
  /** Use testnet (default: false) */
  testnet?: boolean;
}

/**
 * Manages wallet storage, encryption, and signing
 */
export class WalletManager {
  private walletDir: string;
  private testnet: boolean;
  private registry: WalletRegistry | null = null;
  private unlockedWallet: {
    accountId: string;
    seedPhrase: string;
    privateKey: string;
    wallet: Wallet;
  } | null = null;

  constructor(options: WalletManagerOptions = {}) {
    this.walletDir = options.walletDir ?? DEFAULT_WALLET_DIR;
    this.testnet = options.testnet ?? false;
  }

  /**
   * Initialize the wallet manager (creates directories if needed)
   */
  async initialize(): Promise<void> {
    await fs.promises.mkdir(this.walletDir, { recursive: true });
    await this.loadRegistry();
  }

  /**
   * Get list of wallet accounts
   */
  getAccounts(): WalletAccount[] {
    return this.registry?.accounts ?? [];
  }

  /**
   * Get the current account ID
   */
  getCurrentAccountId(): string | null {
    return this.registry?.currentAccountId ?? null;
  }

  /**
   * Check if a wallet is currently unlocked
   */
  isUnlocked(): boolean {
    return this.unlockedWallet !== null;
  }

  /**
   * Get the unlocked wallet (throws if locked)
   */
  getWallet(): Wallet {
    if (!this.unlockedWallet) {
      throw new Error('Wallet is locked');
    }
    return this.unlockedWallet.wallet;
  }

  /**
   * Generate a new seed phrase (24 words)
   */
  generateSeedPhrase(): string {
    return generateSecretKey(256);
  }

  /**
   * Create a new wallet from a seed phrase
   */
  async createWallet(
    seedPhrase: string,
    password: string,
    displayName: string
  ): Promise<WalletAccount> {
    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters');
    }

    // Derive address from seed
    const stacksWallet = await generateStacksWallet({
      secretKey: seedPhrase,
      password: seedPhrase, // wallet-sdk requires this
    });

    const account = stacksWallet.accounts[0];
    const network = this.testnet ? 'testnet' : 'mainnet';
    const address = getAddressFromPrivateKey(account.stxPrivateKey, network);

    // Generate account ID
    const accountId = crypto.randomBytes(16).toString('hex');

    // Encrypt the seed phrase
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const key = crypto.scryptSync(password, salt, SCRYPT_KEYLEN, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
    });

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
      cipher.update(seedPhrase, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    // Create wallet file
    const walletFile: WalletFile = {
      version: WALLET_FILE_VERSION,
      network: this.testnet ? 'testnet' : 'mainnet',
      address,
      displayName,
      createdAt: new Date().toISOString(),
      crypto: {
        salt: salt.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        ciphertext: encrypted.toString('base64'),
        kdf: 'scrypt',
      },
    };

    // Save wallet file
    const walletPath = path.join(this.walletDir, `${accountId}.wallet.json`);
    await fs.promises.writeFile(walletPath, JSON.stringify(walletFile, null, 2));

    // Update registry
    const now = new Date().toISOString();
    const walletAccount: WalletAccount = {
      id: accountId,
      address,
      displayName,
      createdAt: now,
      lastUsed: now,
    };

    if (!this.registry) {
      this.registry = { version: 1, accounts: [], currentAccountId: null };
    }
    this.registry.accounts.push(walletAccount);
    this.registry.currentAccountId = accountId;
    await this.saveRegistry();

    // Auto-unlock the new wallet
    await this.unlock(accountId, password);

    return walletAccount;
  }

  /**
   * Unlock a wallet with password
   */
  async unlock(accountId: string, password: string): Promise<Wallet> {
    const walletPath = path.join(this.walletDir, `${accountId}.wallet.json`);

    let walletFile: WalletFile;
    try {
      const content = await fs.promises.readFile(walletPath, 'utf8');
      walletFile = JSON.parse(content);
    } catch {
      throw new Error('Wallet not found');
    }

    // Decrypt seed phrase
    const salt = Buffer.from(walletFile.crypto.salt, 'base64');
    const iv = Buffer.from(walletFile.crypto.iv, 'base64');
    const tag = Buffer.from(walletFile.crypto.tag, 'base64');
    const ciphertext = Buffer.from(walletFile.crypto.ciphertext, 'base64');

    const key = crypto.scryptSync(password, salt, SCRYPT_KEYLEN, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
    });

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    let seedPhrase: string;
    try {
      seedPhrase = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]).toString('utf8');
    } catch {
      throw new Error('Invalid password');
    }

    // Derive private key from seed
    const stacksWallet = await generateStacksWallet({
      secretKey: seedPhrase,
      password: seedPhrase,
    });
    const privateKey = stacksWallet.accounts[0].stxPrivateKey;

    // Create wallet interface
    const principal = createPrincipal(walletFile.address);
    const wallet: Wallet = {
      principal,
      address: walletFile.address,
      getAddress: () => walletFile.address,
      sign: async (message: Uint8Array): Promise<Uint8Array> => {
        const messageHash = sha256(message);
        const signature = signMessageHashRsv({
          privateKey,
          messageHash: Buffer.from(messageHash).toString('hex'),
        });
        return hexToBytes(signature);
      },
    };

    // Update state
    this.unlockedWallet = {
      accountId,
      seedPhrase,
      privateKey,
      wallet,
    };

    // Update last used
    if (this.registry) {
      const account = this.registry.accounts.find(a => a.id === accountId);
      if (account) {
        account.lastUsed = new Date().toISOString();
      }
      this.registry.currentAccountId = accountId;
      await this.saveRegistry();
    }

    return wallet;
  }

  /**
   * Lock the current wallet
   */
  lock(): void {
    this.unlockedWallet = null;
  }

  /**
   * Delete a wallet account
   */
  async deleteAccount(accountId: string): Promise<void> {
    // Remove wallet file
    const walletPath = path.join(this.walletDir, `${accountId}.wallet.json`);
    try {
      await fs.promises.unlink(walletPath);
    } catch {
      // File may not exist
    }

    // Update registry
    if (this.registry) {
      this.registry.accounts = this.registry.accounts.filter(a => a.id !== accountId);
      if (this.registry.currentAccountId === accountId) {
        this.registry.currentAccountId = this.registry.accounts[0]?.id ?? null;
      }
      await this.saveRegistry();
    }

    // Lock if this was the unlocked wallet
    if (this.unlockedWallet?.accountId === accountId) {
      this.lock();
    }
  }

  /**
   * Export the seed phrase (requires unlocked wallet)
   */
  exportSeedPhrase(): string {
    if (!this.unlockedWallet) {
      throw new Error('Wallet is locked');
    }
    return this.unlockedWallet.seedPhrase;
  }

  private async loadRegistry(): Promise<void> {
    const registryPath = path.join(this.walletDir, 'registry.json');
    try {
      const content = await fs.promises.readFile(registryPath, 'utf8');
      this.registry = JSON.parse(content);
    } catch {
      this.registry = { version: 1, accounts: [], currentAccountId: null };
    }
  }

  private async saveRegistry(): Promise<void> {
    const registryPath = path.join(this.walletDir, 'registry.json');
    await fs.promises.writeFile(registryPath, JSON.stringify(this.registry, null, 2));
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
