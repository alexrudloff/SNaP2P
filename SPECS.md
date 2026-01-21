Stacks‑Native P2P Session & Stream Framework (SNaP2P)

Version: v0.1 (draft)

Audience: Developer AI agent implementing the framework.

Scope: A minimal P2P framework whose “product” is secure sessions, Stacks‑based identity/authentication, and multiplexed opaque byte streams. Applications define everything above raw streams.

Non‑goals (core): discovery/DHT, pubsub, RPC, message framing, file transfer, replication, NAT traversal, relays, interoperability across apps.

Note: The framework MUST ship with a default discoverability module (Section 10) enabled by default in Public mode. Discovery remains out of core.

0. Definitions

Principal: stacks:<address> (Stacks address string; canonical user/node identity).

Locator: a dialable endpoint, e.g. ip:port or dns:port.

Session: an authenticated, encrypted connection between two peers.

Stream: a bidirectional, multiplexed byte channel within a Session.

Wallet: local signing component (you are the wallet). No remote signing.

Chain provider: local pluggable backend for chain reads/broadcast (node RPC, Hiro API, etc.).

1. High‑Level Architecture

1.1 Core responsibilities

The framework MUST provide:

Dial/accept connections using Locator.

Secure channel establishment (confidentiality, integrity, forward secrecy).

Mutual authentication to Stacks principals.

Session lifecycle management (timeouts, keepalive, close, errors).

Stream multiplexing (open/accept/close streams, stream IDs).

The framework MUST NOT interpret application payload bytes.

1.2 Identity model

The only identity exposed to applications is Principal (stacks:<address>).

The secure transport will use an internal keypair for channel crypto; this key is NOT an application identity.

1.3 Dialing model

v0.1 dialing MUST be by ip:port or dns:port (explicit locator).

Dial by stacks:<address> SHOULD be supported via the default discoverability module (Section 10) when running in Public mode.

Private/Stealth nodes MAY disable discoverability entirely; explicit locators MUST remain supported.

1.4 Implementation profiles (normative)

Implementations MAY support any subset of the following roles:

Dialer-only (Client): initiates outbound connections but does not listen for inbound connections.

Listener-only (Server): listens for inbound connections but does not initiate outbound connections.

Full peer: supports both dial and listen.

Requirements:

Every implementation MUST support at least one role (Dialer-only or Listener-only).

Dialer-only implementations MAY ignore PX-1 entirely and remain compliant, provided they support explicit Locator dialing.

If an implementation supports Stealth mode as a Listener, it MUST enforce the Stealth handshake ordering (KNOCK first).

Either party MAY open streams. Implementations MAY refuse inbound stream opens due to local policy or limits, but MUST do so via CLOSE_STREAM with code ERR_STREAM_REFUSED.

2. Cryptography & Authentication

2.1 Transport security

The framework MUST use a modern AEAD secure channel with forward secrecy (e.g., Noise IK/XX or TLS 1.3 / QUIC‑TLS). Implementation choice is flexible, but MUST satisfy:

Confidentiality + integrity.

Forward secrecy.

Resistance to replay (via handshake nonces/transcript binding).

2.2 Two‑tier key model (recommended)

Wallet key: the Stacks principal keypair used to sign attestations and AliasCards. (Local only.)

Node key: an internal keypair used for transport identity and handshake binding (recommended: ed25519). This key MAY be rotated.

2.3 Attestation: wallet binds principal → node public key

Peers authenticate by presenting a wallet‑signed attestation that authorizes their current Node public key.

2.3.1 Attestation object (NodeKeyAttestation v1)

Fields:

v: 1

principal: stacks:<address>

node_pubkey: bytes (ed25519 public key)

issued_at: unix seconds

expires_at: unix seconds (REQUIRED)

nonce: random 16–32 bytes (REQUIRED)

domain: fixed string "snap2p-nodekey-attestation-v1" (REQUIRED)

sig: wallet signature over canonical bytes (REQUIRED)

Rules:

expires_at MUST be in the future at time of use.

A principal MAY authorize multiple node keys simultaneously (multi‑device) — OPTIONAL for v0.1. Default: allow multiple active attestations.

Canonical bytes:

Canonical serialization MUST be unambiguous (recommend: CBOR with deterministic encoding).

The signature input MUST include domain and all fields except sig.

Verification:

Verify wallet signature.

Verify that recovered/derived address from the wallet public key matches principal.

2.4 Session authentication binding

During session establishment, each side MUST prove possession of the node_privkey corresponding to the node_pubkey in the presented attestation.

Binding requirement:

The secure channel handshake MUST be cryptographically bound to node_pubkey (e.g., node key is used as the static identity key in Noise/TLS, OR a post‑handshake signature is made over the transcript hash with node_privkey).

2.5 Mutual authentication

Sessions MUST be mutually authenticated by default.

One‑way auth MAY be a future option; not required in v0.1.

2.6 Time and skew

Implementations MUST tolerate clock skew of ±5 minutes when evaluating issued_at/expires_at.

3. Session Control Plane

3.0 Encoding and interoperability requirements

To ensure language-agnostic interoperability (Rust, JS, Python, etc.), the following apply to all control-plane and PX-1 messages:

All messages MUST be self-delimiting on the wire (length-prefixed or message-oriented transport).

Integer fields MUST have a defined width when sent on the wire (e.g., u64 for stream_id, signed/unsigned MUST NOT be ambiguous).

Timestamps MUST be Unix seconds (int64).

Byte fields are opaque octet sequences; no text encoding is implied.

Strings are UTF-8.

Unknown fields MUST be ignored.

Unknown message types MUST cause a clean error (ERR_VERSION_UNSUPPORTED) or be ignored if explicitly marked optional.

Serialization format (CBOR, JSON, Protobuf, etc.) is explicitly out of scope and MUST NOT be assumed.



The framework defines a small control plane for session establishment and stream management.

3.1 Message framing (control plane only)

Control plane messages MUST have explicit boundaries. Use one of:

Length‑prefixed frames (varint length + bytes), or

Underlying transport message boundaries if provided.

Applications do NOT inherit this framing; application streams are raw bytes.

3.2 Control messages

All control messages are exchanged on a reserved control channel (implementation‑defined) before application streams are allowed.

3.2.1 HELLO

Fields:

proto_v: 1

nonce: random

capabilities: list of framework feature flags (e.g., stealth, aliases)

3.2.2 AUTH

Fields:

principal

attestation (NodeKeyAttestation v1)

session_nonce: echo both sides’ nonces

3.2.3 AUTH_OK / AUTH_FAIL

AUTH_OK indicates session is established.

AUTH_FAIL includes error code and closes session.

3.2.4 OPEN_STREAM

Fields:

stream_id: u64

label: optional UTF‑8 string (debug routing only)

3.2.5 CLOSE_STREAM

Fields:

stream_id

code: enum

3.2.6 PING / PONG

Keepalive.

3.3 Error codes (minimal)

ERR_VERSION_UNSUPPORTED

ERR_AUTH_INVALID

ERR_AUTH_EXPIRED

ERR_INVITE_REQUIRED

ERR_INVITE_INVALID

ERR_NOT_ALLOWED

ERR_RATE_LIMITED

`ERR_STREAM_REFUSED``

4. Visibility Modes (Public / Private / Stealth)

Visibility is a node policy affecting discovery surfaces and pre‑auth metadata.

4.1 Mode definitions

4.1.1 Public

Node may participate in optional discovery/resolvers (out of scope v0.1).

May reveal non‑sensitive metadata pre‑auth.

4.1.2 Private

Node MUST NOT publish or forward endpoint advertisements (if any resolver exists).

Node MUST NOT answer resolver queries (future).

Node is reachable only via explicit Locator shared out‑of‑band.

Node SHOULD default to allowlist gating post‑auth.

4.1.3 Stealth

All Private rules PLUS:

Node MUST minimize pre‑auth metadata.

Node SHOULD require an Invite Token before performing expensive auth/crypto.

Node MUST rate‑limit unauthenticated handshakes.

4.2 Invite Tokens

Invite Tokens are shared out‑of‑band along with Locator.

4.2.1 Token forms

Opaque token: random 128–256 bits.

Signed invite (optional): principal‑signed invite with expiry.

v0.1 default: opaque token.

4.2.2 Token lifecycle

Tokens MAY be one‑time or reusable. v0.1: reusable with expiry (server policy).

Server stores token set locally.

4.3 Stealth handshake order (normative)

Goal: avoid leaking alias/meta and avoid expensive work for scanners.

Step 0: TCP/QUIC connect

Client connects via Locator.

Step 1: KNOCK (pre‑auth)

Client sends KNOCK message immediately.
Fields:

proto_v: 1

knock_nonce: random

invite_token: bytes

Server behavior:

If invite token is missing/invalid: respond AUTH_FAIL{ERR_INVITE_INVALID} and close.

If valid: proceed.

Step 2: Lightweight HELLO

Server sends minimal HELLO (no alias, no descriptive metadata).
Fields:

proto_v: 1

server_nonce: random

capabilities: minimal

Step 3: Secure channel handshake

Perform Noise/TLS/QUIC handshake.

Step 4: AUTH exchange

Client sends AUTH with principal + attestation.
Server verifies attestation and that the secure channel is bound to the node pubkey.
Server replies with its AUTH.

Step 5: Allowlist gate (recommended)

In Private/Stealth modes, server SHOULD enforce allowlist after auth:

If remote_principal not allowed: AUTH_FAIL{ERR_NOT_ALLOWED} and close.

Step 6: AUTH_OK

After successful mutual auth (and allowlist), send AUTH_OK.

Step 7: Post‑auth metadata (optional)

Only after AUTH_OK may the server provide:

AliasCard

Node description

Supported optional modules

5. Streams

5.1 Properties

Streams are opaque bytes.

Stream IDs are u64.

Either side may open streams.

5.2 Labels

label is optional and MUST NOT be relied on for security.

Used only for app routing/debug.

5.3 Limits

Implementations SHOULD support:

max concurrent streams (configurable)

per-stream and per-session rate limits (esp. for pre-auth in stealth)

5.4 Minimum Dialer-only client checklist (non-normative)

A minimal Dialer-only client implementation requires only:

outbound dialing via ip:port or dns:port

control-plane handshake (including KNOCK when required)

Stacks principal authentication

stream open/close

read/write opaque bytes on streams

No inbound listening, discovery, or PX-1 support is required.

6. Aliases Module (Self-asserted, Signed) (Self‑asserted, Signed)

6.1 Requirements

Alias claims MUST be self‑asserted: only the principal can sign its alias.

Aliases are NOT unique.

Exactly one active alias per principal (latest issued_at wins).

6.2 AliasCard v1

Fields:

v: 1

principal: stacks:<address>

alias: normalized handle (UTF‑8 allowed; recommended normalization: NFKC + lowercase + trim)

display_name: UTF‑8 (emoji allowed)

issued_at: unix seconds

expires_at: unix seconds (REQUIRED)

nonce: random (REQUIRED)

domain: "snap2p-aliascard-v1"

sig: wallet signature over canonical bytes

TTL guidance:

Default TTL: 7 days (configurable).

Refresh:

On reconnection, peers SHOULD exchange fresh AliasCards.

Expired AliasCards MUST NOT be displayed as current.

7. Local Wallet & Chain Provider (Non-normative)

Wallet and chain access are local-only concerns and are not exposed over P2P by the framework.

This section is informative only and defines no wire protocol.

Suggested local interfaces (names are illustrative):

Wallet: get_principal(), sign_message(domain, payload), sign_transaction(tx)

Chain provider: get_balance(principal), get_nonce(principal), call_readonly(...), broadcast_tx(signed_tx)

Implementations MAY use a local node RPC, a third-party API, or any other backend. Provider correctness verification is out of scope for v0.1.

8. Security Requirements & Threat Model Notes

8.1 Must‑haves

Mutual auth by default.

Transcript/nonces to prevent replay.

No silent downgrade of crypto or protocol version.

Bind Stacks principal (via attestation) to the secure session.

Allowlist gating recommended for Private/Stealth.

8.2 Expected properties

Prevent impersonation of principals.

Provide confidentiality/integrity of stream bytes.

Availability is not guaranteed.

Metadata privacy is limited when dialing direct locators.

9. Implementation Notes (Non-normative)

This specification is language- and runtime-agnostic. Any implementation that satisfies the normative requirements (MUST/SHOULD/MAY) is compliant.

A minimal conforming implementation requires:

one secure channel implementation

one stream multiplexing implementation

the control-plane messages defined herein

10. Default Discoverability Module (PX‑1)

PX‑1 is a first‑party optional module shipped with the framework. It enables best‑effort connect‑by‑principal using only existing authenticated peer connections (social‑graph exchange). PX‑1 is enabled by default for Public nodes.

PX‑1 is intentionally minimal:

No DHT.

No global directory.

No NAT traversal or relays.

No cryptographic authority beyond the authenticated session.

10.1 Operation

PX‑1 runs post‑auth (after AUTH_OK) on an application stream labeled "px-1".

PX‑1 defines only three messages. Encoding is application-defined but MUST be self-delimiting.

PX_RESOLVE_REQ { principal, max_results? }

PX_RESOLVE_RESP { locators[] }

PX_PUSH { principal, locators[], ttl_seconds } (optional)

10.2 Semantics

A locator is dns:port or ip:port.

PX‑1 data are routing hints only. Identity is established exclusively by session authentication after dialing.

Nodes MAY maintain a local cache: principal -> {locators, expires_at}.

Default TTL guidance: 24 hours (configurable).

10.3 Policy interactions (normative)

Public: MAY answer resolve requests; MAY push hints; MAY include hints about itself.

Private: MUST NOT push hints about itself; MAY answer resolve for others; MUST NOT advertise outside existing authenticated sessions.

Stealth: PX‑1 SHOULD be disabled by default; if enabled, MUST NOT push hints about itself and MUST enforce allowlist gating before answering resolve.

11. Open Items (for v0.2) (for v0.2)

Resolver modules beyond PX‑1 (on‑chain pointers, BNS, optional DHT).

Optional permissions module.

Optional community relay transport.

Optional chain provider verification and multi‑provider cross‑check.

