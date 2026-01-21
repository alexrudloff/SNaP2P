/**
 * Type definitions for SNaP2P protocol
 */

export type { Principal } from './principal.js';
export {
  createPrincipal,
  parsePrincipal,
  formatPrincipal,
  isValidStacksAddress,
  principalsEqual,
} from './principal.js';

export type { Locator } from './locator.js';
export {
  parseLocator,
  formatLocator,
  createLocator,
} from './locator.js';

export {
  ErrorCode,
  getErrorMessage,
  SNaP2PError,
} from './errors.js';

export {
  MessageType,
  VisibilityMode,
} from './messages.js';
export type {
  BaseMessage,
  HelloMessage,
  AuthMessage,
  AuthOkMessage,
  AuthFailMessage,
  OpenStreamMessage,
  CloseStreamMessage,
  StreamDataMessage,
  PingMessage,
  PongMessage,
  KnockMessage,
  KnockResponseMessage,
  ErrorMessage,
  Message,
} from './messages.js';
