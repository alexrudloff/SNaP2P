/**
 * High-level Peer API for SNaP2P
 * Provides a simple interface for establishing connections and managing streams.
 */

import * as net from 'node:net';
import { EventEmitter } from 'node:events';
import { NodeKeyPair, generateNodeKeyPair } from '../crypto/keys.js';
import { Wallet, WalletProvider, wrapWalletProvider, generateWallet } from '../identity/wallet.js';
import { NodeKeyAttestation, createAttestation } from '../identity/attestation.js';
import { Principal, formatPrincipal } from '../types/principal.js';
import { Locator, parseLocator, formatLocator } from '../types/locator.js';
import { VisibilityMode } from '../types/messages.js';
import { dial, configureSocket } from './dialer.js';
import { Listener, listen } from './listener.js';
import { Session } from '../session/session.js';
import { performInitiatorHandshake, performResponderHandshake, HandshakeConfig } from '../session/handshake.js';
import { Multiplexer, MultiplexerConfig } from '../stream/multiplexer.js';
import { SNaP2PStream } from '../stream/snap2p-stream.js';

export interface PeerConfig {
  /**
   * Wallet for signing attestations.
   * Can be a full Wallet or a minimal WalletProvider (for external wallet integration).
   */
  wallet?: Wallet | WalletProvider;
  /** Node keypair (generated if not provided) */
  nodeKeys?: NodeKeyPair;
  /** Visibility mode */
  visibility?: VisibilityMode;
  /** Use testnet addresses */
  testnet?: boolean;
  /** Allowlist of principals (for Private/Stealth modes) */
  allowlist?: string[];
  /** Handshake timeout in ms */
  handshakeTimeoutMs?: number;
  /** Maximum streams per session */
  maxStreamsPerSession?: number;
}

export interface ConnectionInfo {
  session: Session;
  multiplexer: Multiplexer;
  remotePrincipal: Principal;
}

export interface PeerEvents {
  connection: [info: ConnectionInfo];
  listening: [locator: Locator];
  error: [error: Error];
  close: [];
}

/**
 * SNaP2P Peer - the main entry point for the library
 */
export class Peer extends EventEmitter<PeerEvents> {
  readonly principal: Principal;
  readonly nodePublicKey: Uint8Array;

  private wallet: Wallet;
  private nodeKeys: NodeKeyPair;
  private attestation: NodeKeyAttestation | null = null;
  private listener: Listener | null = null;
  private connections: Map<string, ConnectionInfo> = new Map();
  private config: Required<Omit<PeerConfig, 'wallet' | 'nodeKeys' | 'allowlist'>> & { allowlist?: Set<string> };
  private privateKey: string | null = null;

  private constructor(wallet: Wallet, nodeKeys: NodeKeyPair, config: PeerConfig) {
    super();

    this.wallet = wallet;
    this.nodeKeys = nodeKeys;
    this.principal = wallet.principal;
    this.nodePublicKey = nodeKeys.publicKey;

    this.config = {
      visibility: config.visibility ?? VisibilityMode.PUBLIC,
      testnet: config.testnet ?? false,
      handshakeTimeoutMs: config.handshakeTimeoutMs ?? 30000,
      maxStreamsPerSession: config.maxStreamsPerSession ?? 100,
      allowlist: config.allowlist ? new Set(config.allowlist) : undefined,
    };
  }

  /**
   * Create a new peer with generated or provided wallet.
   *
   * If no wallet is provided, generates an ephemeral wallet.
   * Accepts either a full Wallet or a minimal WalletProvider (for external integration).
   */
  static async create(config: PeerConfig = {}): Promise<Peer> {
    const nodeKeys = config.nodeKeys ?? generateNodeKeyPair();

    let wallet: Wallet;
    if (config.wallet) {
      // Check if it's a full Wallet or just a WalletProvider
      if ('principal' in config.wallet) {
        wallet = config.wallet as Wallet;
      } else {
        // Wrap the WalletProvider into a full Wallet
        wallet = wrapWalletProvider(config.wallet);
      }
    } else {
      const generated = generateWallet({ testnet: config.testnet });
      wallet = generated.wallet;
    }

    const peer = new Peer(wallet, nodeKeys, config);

    // Create attestation
    peer.attestation = await createAttestation(wallet, nodeKeys.publicKey);

    return peer;
  }

  /**
   * Create a peer for testing with a known private key
   */
  static async createWithPrivateKey(
    privateKey: string,
    config: PeerConfig = {}
  ): Promise<Peer> {
    const { createWallet } = await import('../identity/wallet.js');
    const wallet = createWallet(privateKey, { testnet: config.testnet });
    const nodeKeys = config.nodeKeys ?? generateNodeKeyPair();

    const peer = new Peer(wallet, nodeKeys, config);
    peer.privateKey = privateKey;
    peer.attestation = await createAttestation(wallet, nodeKeys.publicKey);

    return peer;
  }

  /**
   * Start listening for incoming connections
   */
  async listen(port: number, host: string = '0.0.0.0'): Promise<Locator> {
    if (this.listener) {
      throw new Error('Already listening');
    }

    return new Promise((resolve, reject) => {
      this.listener = listen({ port, host });

      this.listener.on('listening', (locator) => {
        this.emit('listening', locator);
        resolve(locator);
      });

      this.listener.on('error', (err) => {
        this.emit('error', err);
        reject(err);
      });

      this.listener.on('connection', async (socket, remote) => {
        try {
          configureSocket(socket);
          await this.handleIncomingConnection(socket, remote);
        } catch (err) {
          this.emit('error', err instanceof Error ? err : new Error(String(err)));
          socket.destroy();
        }
      });
    });
  }

  /**
   * Stop listening for connections
   */
  async stopListening(): Promise<void> {
    if (this.listener) {
      await this.listener.close();
      this.listener = null;
    }
  }

  /**
   * Dial a remote peer
   */
  async dial(target: string | Locator): Promise<ConnectionInfo> {
    const locator = typeof target === 'string' ? parseLocator(target) : target;

    const socket = await dial(locator, { timeout: this.config.handshakeTimeoutMs });
    configureSocket(socket);

    const handshakeConfig: HandshakeConfig = {
      timeoutMs: this.config.handshakeTimeoutMs,
      visibility: this.config.visibility,
      allowlist: this.config.allowlist,
    };

    const result = await performInitiatorHandshake(
      socket,
      this.nodeKeys,
      this.attestation!,
      handshakeConfig
    );

    const session = new Session(
      socket,
      result.noiseState,
      this.principal,
      result.remotePrincipal,
      result.remoteAttestation,
      result.sessionId,
      true
    );

    const multiplexer = new Multiplexer(session, {
      maxStreams: this.config.maxStreamsPerSession,
    });

    const connectionId = formatLocator(locator);
    const info: ConnectionInfo = {
      session,
      multiplexer,
      remotePrincipal: result.remotePrincipal,
    };

    this.connections.set(connectionId, info);

    session.on('close', () => {
      this.connections.delete(connectionId);
    });

    this.emit('connection', info);
    return info;
  }

  /**
   * Open a stream on an existing connection
   */
  openStream(connectionId: string, label?: string): SNaP2PStream {
    const info = this.connections.get(connectionId);
    if (!info) {
      throw new Error(`No connection with ID: ${connectionId}`);
    }
    return info.multiplexer.openStream(label);
  }

  /**
   * Get a connection by ID
   */
  getConnection(connectionId: string): ConnectionInfo | undefined {
    return this.connections.get(connectionId);
  }

  /**
   * Get all active connections
   */
  getAllConnections(): ConnectionInfo[] {
    return Array.from(this.connections.values());
  }

  /**
   * Close a specific connection
   */
  closeConnection(connectionId: string): void {
    const info = this.connections.get(connectionId);
    if (info) {
      info.session.close();
      this.connections.delete(connectionId);
    }
  }

  /**
   * Close all connections and stop listening
   */
  async close(): Promise<void> {
    for (const info of this.connections.values()) {
      info.session.close();
    }
    this.connections.clear();

    await this.stopListening();
    this.emit('close');
  }

  /**
   * Check if peer is listening
   */
  get isListening(): boolean {
    return this.listener?.listening ?? false;
  }

  /**
   * Get the listening address
   */
  get listeningAddress(): Locator | null {
    return this.listener?.address ?? null;
  }

  /**
   * Get connection count
   */
  get connectionCount(): number {
    return this.connections.size;
  }

  private async handleIncomingConnection(socket: net.Socket, remote: Locator): Promise<void> {
    const handshakeConfig: HandshakeConfig = {
      timeoutMs: this.config.handshakeTimeoutMs,
      visibility: this.config.visibility,
      allowlist: this.config.allowlist,
    };

    const result = await performResponderHandshake(
      socket,
      this.nodeKeys,
      this.attestation!,
      handshakeConfig
    );

    const session = new Session(
      socket,
      result.noiseState,
      this.principal,
      result.remotePrincipal,
      result.remoteAttestation,
      result.sessionId,
      false
    );

    const multiplexer = new Multiplexer(session, {
      maxStreams: this.config.maxStreamsPerSession,
    });

    const connectionId = formatLocator(remote);
    const info: ConnectionInfo = {
      session,
      multiplexer,
      remotePrincipal: result.remotePrincipal,
    };

    this.connections.set(connectionId, info);

    session.on('close', () => {
      this.connections.delete(connectionId);
    });

    this.emit('connection', info);
  }
}
