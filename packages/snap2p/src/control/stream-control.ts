/**
 * Stream control messages
 */

import {
  MessageType,
  OpenStreamMessage,
  CloseStreamMessage,
  StreamDataMessage,
} from '../types/messages.js';
import { ErrorCode } from '../types/errors.js';

/**
 * Create an OPEN_STREAM message
 */
export function createOpenStreamMessage(
  streamId: bigint,
  label?: string
): OpenStreamMessage {
  return {
    type: MessageType.OPEN_STREAM,
    streamId,
    label,
  };
}

/**
 * Create a CLOSE_STREAM message
 */
export function createCloseStreamMessage(
  streamId: bigint,
  errorCode?: ErrorCode
): CloseStreamMessage {
  return {
    type: MessageType.CLOSE_STREAM,
    streamId,
    errorCode,
  };
}

/**
 * Create a STREAM_DATA message
 */
export function createStreamDataMessage(
  streamId: bigint,
  data: Uint8Array,
  fin: boolean = false
): StreamDataMessage {
  return {
    type: MessageType.STREAM_DATA,
    streamId,
    data,
    fin: fin || undefined,
  };
}
