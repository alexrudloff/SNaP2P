# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SNaP2P (Stacks-Native P2P Session & Stream Framework) is a minimal P2P framework providing secure sessions between peers with Stacks-based identity/authentication and multiplexed opaque byte streams. Applications define everything above raw streams.

**Current Status:** Implementation complete (Phases 1-6).

**Source of Truth:** `SPECS.md` contains the complete protocol specification.

## Project Structure

```
stacks-p2p/
├── packages/
│   ├── snap2p/           # Core library (no UI dependencies)
│   └── snap2p-demo/      # Demo CLI with Ink UI
```

## Architecture

### Core Components

1. **Identity Model**
   - Principal: `stacks:<address>` (canonical identity)
   - Two-tier keys: Wallet key (signs attestations) + Node key (transport identity, ed25519)
   - NodeKeyAttestation v1 binds principal to node public key

2. **Session Establishment**
   - Noise XX handshake for mutual authentication with forward secrecy
   - All traffic encrypted with ChaCha20-Poly1305
   - Replay protection via handshake transcript binding

3. **Stream Multiplexing**
   - Bidirectional byte channels within sessions
   - Stream IDs are u64
   - Either peer can open streams
   - Optional labels for routing/debugging only

4. **Control Plane Messages**
   - HELLO, AUTH, AUTH_OK/AUTH_FAIL, OPEN_STREAM, CLOSE_STREAM, PING/PONG
   - All messages are length-prefixed and encrypted

### Wallet Management

- BIP39 24-word seed phrase generation
- AES-256-GCM encryption with scrypt KDF
- Multi-account registry stored in `~/.snap2p/wallets/`

### Key Properties

- **Direct connections** - No relays, no DHT, no routing through other peers
- **End-to-end encrypted** - All traffic encrypted with Noise session keys
- **Authenticated** - Stacks wallet signs attestation binding identity to node
- **Multiplexed** - Multiple streams per connection
- **Minimal** - Framework doesn't interpret payload bytes

## Key Constraints

- Clock skew tolerance: ±5 minutes for timestamp validation
- Integer fields must have defined width on wire (u64 for stream_id, int64 for timestamps)
- Strings are UTF-8, bytes are opaque octets
- Unknown fields must be ignored; unknown message types cause ERR_VERSION_UNSUPPORTED
- Serialization format: CBOR (deterministic encoding via cborg)
- Framework must NOT interpret application payload bytes

## Quick Start

```bash
# Build
pnpm build

# Terminal 1 - Echo server
node packages/snap2p-demo/dist/index.js listen 9000

# Terminal 2 - Chat client
node packages/snap2p-demo/dist/index.js chat 127.0.0.1:9000

# Interactive sign-in (Ink UI)
node packages/snap2p-demo/dist/index.js signin
```

## Non-Goals for v0.1

Discovery/DHT (beyond PX-1), pubsub, RPC, message framing, file transfer, replication, NAT traversal, relays, interoperability across apps.
