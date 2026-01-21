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
