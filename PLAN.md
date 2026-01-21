# SNP2P Demo Implementation Plan

TypeScript/Node.js implementation of the SNP2P specification with a working demo application.

## Phase 1: Foundation

1. **Project setup**: Node.js + TypeScript, ESM modules, monorepo structure
2. **Dependencies**:
   - `@stacks/transactions` - Stacks signing/address utilities
   - `@noble/ciphers` + `@noble/curves` - Noise protocol primitives
   - `cbor-x` - deterministic CBOR encoding
3. **Wire protocol**: Length-prefixed messages over TCP
4. **Basic `Peer` class**: dial(locator) and listen(port)

## Phase 2: Identity & Auth

5. **NodeKeyAttestation v1**: Create, serialize (CBOR), sign with Stacks wallet
6. **Attestation verification**: Signature check + address derivation + expiry check
7. **Control messages**: HELLO, AUTH, AUTH_OK, AUTH_FAIL as typed objects
8. **Handshake flow**: Exchange HELLO → AUTH → verify → AUTH_OK
9. **Noise IK handshake**: Secure channel with forward secrecy, bound to node keys

## Phase 3: Streams

10. **Stream multiplexer**: Map of stream_id → duplex stream
11. **OPEN_STREAM / CLOSE_STREAM** handling with error codes
12. **Backpressure**: Node.js streams with proper flow control
13. **PING/PONG**: Keepalive on control channel

## Phase 4: Demo App

14. **Echo server**: Listener that echoes back stream data
15. **Chat CLI**: Two peers can send messages over a stream
16. **Identity display**: Show authenticated `stacks:<address>` on connect
17. **CLI commands**: `listen`, `dial`, `chat`

## Phase 5: Visibility Modes (Future)

- **Public mode**: Default configuration, allows metadata sharing
- **Private mode**: Allowlist gating, no discovery participation
- **Stealth mode**:
  - KNOCK message with invite token validation
  - Invite token generation and lifecycle management
  - Rate limiting for unauthenticated handshakes
  - Minimal pre-auth metadata exposure

## Phase 6: Aliases Module (Future)

- **AliasCard v1**: Create, serialize, sign with wallet
- **Alias exchange**: Post-AUTH_OK metadata sharing
- **Alias validation**: Signature verification, expiry handling
- **TTL management**: Default 7-day TTL, refresh on reconnection

## Phase 7: PX-1 Discovery (Future)

- **PX-1 stream**: Labeled stream "px-1" for peer exchange
- **Messages**: PX_RESOLVE_REQ, PX_RESOLVE_RESP, PX_PUSH
- **Local cache**: principal → {locators, expires_at}
- **Policy enforcement**: Public/Private/Stealth rules for sharing
- **Dial by principal**: Resolve principal to locator via connected peers

## Phase 8: Production Hardening (Future)

- **Session lifecycle**: Configurable timeouts, graceful close, error recovery
- **Stream limits**: Max concurrent streams, per-stream rate limits
- **Multi-device**: Multiple active attestations per principal
- **Clock skew handling**: ±5 minute tolerance enforcement
- **Unknown field handling**: Ignore unknown fields, ERR_VERSION_UNSUPPORTED for unknown messages

## Deliverables

### Library Package (`snp2p`)
- Core peer/session/stream abstractions
- Stacks identity and attestation utilities
- Wire protocol encoding/decoding

### Demo CLI (`snp2p-demo`)
- `listen <port>` - Start a listener
- `dial <host:port>` - Connect to a peer
- `chat <host:port>` - Interactive chat session

### Example Usage
```bash
# Terminal 1: Start listener
npx snp2p-demo listen 9000

# Terminal 2: Connect and chat
npx snp2p-demo chat 127.0.0.1:9000
```
