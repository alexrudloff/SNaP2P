/**
 * SNaP2P - Stacks-Native P2P Session & Stream Framework
 *
 * A minimal P2P framework providing secure sessions between peers
 * with Stacks-based identity/authentication and multiplexed opaque byte streams.
 */

// Core types
export * from './types/index.js';

// Wire protocol
export * from './wire/index.js';

// Cryptographic primitives
export * from './crypto/index.js';

// Identity management
export * from './identity/index.js';

// Control messages
export * from './control/index.js';

// Session management
export * from './session/index.js';

// Stream multiplexing
export * from './stream/index.js';

// Peer API (main entry point)
export * from './peer/index.js';
