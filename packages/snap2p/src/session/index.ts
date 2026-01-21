/**
 * Session management exports
 */

export type { HandshakeConfig, HandshakeResult } from './handshake.js';
export {
  performInitiatorHandshake,
  performResponderHandshake,
} from './handshake.js';

export type { SessionConfig, SessionEvents } from './session.js';
export { Session } from './session.js';
