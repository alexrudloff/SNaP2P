# SNaP2P

**Stacks-Native P2P Session & Stream Framework**

A minimal peer-to-peer framework providing secure, authenticated sessions between peers using Stacks blockchain identity with multiplexed encrypted byte streams.

## What It Does

SNaP2P gives you direct, encrypted connections between peers where:

- **Identity is a Stacks address** - Your STX wallet is your identity/user identifier
- **Everything is encrypted** - Noise XX handshake with ChaCha20-Poly1305 transport
- **Streams are just bytes** - Send chat messages, files, game state, whatever you want
- **No middlemen** - Direct peer-to-peer TCP connections, no relays or servers

```
┌─────────────────────────────────────────────────────┐
│  Your Application                                   │
│  (chat, file transfer, games, RPC, etc.)            │
├─────────────────────────────────────────────────────┤
│  SNaP2P Stream (encrypted opaque bytes)             │
├─────────────────────────────────────────────────────┤
│  SNaP2P Session                                     │
│  - Noise XX mutual authentication                   │
│  - Stacks wallet signs node key attestation         │
├─────────────────────────────────────────────────────┤
│  TCP                                                │
└─────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install dependencies
pnpm install

# Build
pnpm build

# Terminal 1 - Start a listener
node packages/snap2p-demo/dist/index.js listen 9000

# Terminal 2 - Connect and chat
node packages/snap2p-demo/dist/index.js chat 127.0.0.1:9000
```

You'll see both peers authenticate with their Stacks addresses, then you can send messages back and forth over the encrypted connection.

## Using the Library

```typescript
import { Peer, formatPrincipal } from 'snap2p';

// Create a peer (generates ephemeral wallet)
const peer = await Peer.create();
console.log(`I am: ${formatPrincipal(peer.principal)}`);

// Listen for connections
await peer.listen(9000);

peer.on('connection', (conn) => {
  console.log(`Connected: ${formatPrincipal(conn.remotePrincipal)}`);

  // Handle incoming streams
  conn.multiplexer.on('stream', (stream) => {
    stream.on('data', (data) => {
      console.log('Received:', data.toString());
      stream.write(data); // Echo back
    });
  });
});

// Or dial out to another peer
const conn = await peer.dial('192.168.1.100:9000');
const stream = conn.multiplexer.openStream('my-protocol');
stream.write(Buffer.from('Hello!'));
```

## Wallet Management

SNaP2P includes built-in wallet management with encrypted storage:

```bash
# Interactive sign-in (creates/restores/unlocks wallet)
node packages/snap2p-demo/dist/index.js signin

# Or use CLI commands
node packages/snap2p-demo/dist/index.js wallet create
node packages/snap2p-demo/dist/index.js wallet list

# Use a saved wallet
node packages/snap2p-demo/dist/index.js listen 9000 -w MyWallet
```

Wallets are stored in `~/.snap2p/wallets/` with:
- BIP39 24-word seed phrases
- AES-256-GCM encryption with scrypt KDF
- Multi-account support

## Project Structure

```
packages/
├── snap2p/          # Core library (no UI dependencies)
│   └── src/
│       ├── crypto/      # Noise XX, Ed25519 keys
│       ├── identity/    # Wallet, attestations
│       ├── session/     # Handshake, encrypted sessions
│       ├── stream/      # Multiplexer, Duplex streams
│       └── peer/        # High-level Peer API
│
└── snap2p-demo/     # Demo CLI with Ink terminal UI
    └── src/
        ├── components/  # React/Ink UI components
        └── commands/    # CLI commands
```

## How Authentication Works

1. Each peer has an **Ed25519 node key** (ephemeral, for transport)
2. Your **Stacks wallet** signs a `NodeKeyAttestation` binding your address to the node key
3. During connection, peers exchange attestations and verify signatures
4. The Noise XX handshake provides mutual authentication and forward secrecy
5. All subsequent traffic is encrypted with session keys

This means you can prove "I am `SP2K8Z...`" to any peer, and they can prove their identity to you.

## Key Properties

| Property | Description |
|----------|-------------|
| **Direct** | Point-to-point TCP, no routing through other peers |
| **Encrypted** | All traffic encrypted (ChaCha20-Poly1305) |
| **Authenticated** | Stacks addresses verified via signed attestations |
| **Multiplexed** | Multiple streams per connection |
| **Minimal** | Framework doesn't interpret your payload bytes |

## What SNaP2P Doesn't Do

This is intentionally minimal. Not included:

- Discovery / DHT
- Relays / NAT traversal
- Pub/sub
- RPC / message framing
- File transfer protocols

You build those on top of the encrypted streams if you need them.

## License

MIT
