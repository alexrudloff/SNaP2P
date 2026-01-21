/**
 * Control plane message handling
 */

export {
  PROTOCOL_VERSION,
  createHelloMessage,
  createAuthMessage,
  createAuthOkMessage,
  createAuthFailMessage,
  createPingMessage,
  createPongMessage,
  createErrorMessage,
  validateHelloMessage,
} from './messages.js';

export {
  createOpenStreamMessage,
  createCloseStreamMessage,
  createStreamDataMessage,
} from './stream-control.js';

export type { KeepaliveConfig } from './keepalive.js';
export { KeepaliveManager } from './keepalive.js';

// Stealth mode support per SPECS 4.3
export type { InviteTokenConfig } from './stealth.js';
export {
  InviteTokenManager,
  createKnockMessage,
  createKnockResponseMessage,
  createInviteFailMessage,
  createInviteRequiredMessage,
} from './stealth.js';
