/**
 * Wire protocol encoding and framing
 */

export {
  encodeMessage,
  decodeMessage,
  encode,
  decode,
} from './codec.js';

export {
  encodeVarint,
  decodeVarint,
  frameMessage,
  parseFramedMessage,
  FrameBuffer,
} from './framing.js';
export type { ParseResult } from './framing.js';
