/**
 * CBOR codec for SNaP2P messages.
 * Uses cborg for deterministic encoding (required for attestation signatures).
 */

import * as cborg from 'cborg';
import {
  Message,
  MessageType,
  VisibilityMode,
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
} from '../types/messages.js';
import { ErrorCode, SNaP2PError } from '../types/errors.js';

/**
 * Encode options for deterministic CBOR
 */
const encodeOptions: cborg.EncodeOptions = {
  // Use canonical/deterministic encoding
  float64: true,
  // Sort map keys for determinism
  mapSorter: (a: [unknown, unknown], b: [unknown, unknown]) => {
    const keyA = String(a[0]);
    const keyB = String(b[0]);
    return keyA < keyB ? -1 : keyA > keyB ? 1 : 0;
  },
};

/**
 * CBOR representation of messages for wire encoding
 */
interface WireMessage {
  t: number; // type
  [key: string]: unknown;
}

/**
 * Encode a message to CBOR bytes
 */
export function encodeMessage(message: Message): Uint8Array {
  const wire = messageToWire(message);
  return cborg.encode(wire, encodeOptions);
}

/**
 * Decode CBOR bytes to a message
 */
export function decodeMessage(data: Uint8Array): Message {
  const wire = cborg.decode(data) as WireMessage;
  return wireToMessage(wire);
}

/**
 * Encode arbitrary data to deterministic CBOR
 */
export function encode(data: unknown): Uint8Array {
  return cborg.encode(data, encodeOptions);
}

/**
 * Decode CBOR bytes to arbitrary data
 */
export function decode<T = unknown>(data: Uint8Array): T {
  return cborg.decode(data) as T;
}

/**
 * Convert internal message to wire format
 */
function messageToWire(message: Message): WireMessage {
  switch (message.type) {
    case MessageType.HELLO:
      return {
        t: message.type,
        v: message.version,
        pk: message.nodePublicKey,
        n: message.nonce,
        ts: message.timestamp,
        vis: message.visibility,
        cap: message.capabilities,
      };

    case MessageType.AUTH:
      return {
        t: message.type,
        att: message.attestation,
        hd: message.handshakeData,
      };

    case MessageType.AUTH_OK:
      return {
        t: message.type,
        p: message.principal,
        sid: message.sessionId,
      };

    case MessageType.AUTH_FAIL:
      return {
        t: message.type,
        ec: message.errorCode,
        ...(message.reason && { r: message.reason }),
      };

    case MessageType.OPEN_STREAM:
      return {
        t: message.type,
        sid: message.streamId,
        ...(message.label && { l: message.label }),
      };

    case MessageType.CLOSE_STREAM:
      return {
        t: message.type,
        sid: message.streamId,
        ...(message.errorCode !== undefined && { ec: message.errorCode }),
      };

    case MessageType.STREAM_DATA:
      return {
        t: message.type,
        sid: message.streamId,
        d: message.data,
        ...(message.fin && { f: message.fin }),
      };

    case MessageType.PING:
      return {
        t: message.type,
        seq: message.sequence,
        ts: message.timestamp,
      };

    case MessageType.PONG:
      return {
        t: message.type,
        seq: message.sequence,
        ts: message.timestamp,
      };

    case MessageType.KNOCK:
      return {
        t: message.type,
        it: message.inviteToken,
      };

    case MessageType.KNOCK_RESPONSE:
      return {
        t: message.type,
        a: message.allowed,
      };

    case MessageType.ERROR:
      return {
        t: message.type,
        ec: message.errorCode,
        ...(message.reason && { r: message.reason }),
      };
  }
}

/**
 * Convert wire format to internal message
 */
function wireToMessage(wire: WireMessage): Message {
  const type = wire.t as MessageType;

  switch (type) {
    case MessageType.HELLO:
      return {
        type: MessageType.HELLO,
        version: wire.v as number,
        nodePublicKey: wire.pk as Uint8Array,
        nonce: wire.n as Uint8Array,
        timestamp: BigInt(wire.ts as number | bigint),
        visibility: wire.vis as VisibilityMode,
        capabilities: (wire.cap as string[]) ?? [],
      } satisfies HelloMessage;

    case MessageType.AUTH:
      return {
        type: MessageType.AUTH,
        attestation: wire.att as Uint8Array,
        handshakeData: wire.hd as Uint8Array,
      } satisfies AuthMessage;

    case MessageType.AUTH_OK:
      return {
        type: MessageType.AUTH_OK,
        principal: wire.p as string,
        sessionId: wire.sid as Uint8Array,
      } satisfies AuthOkMessage;

    case MessageType.AUTH_FAIL:
      return {
        type: MessageType.AUTH_FAIL,
        errorCode: wire.ec as ErrorCode,
        reason: wire.r as string | undefined,
      } satisfies AuthFailMessage;

    case MessageType.OPEN_STREAM:
      return {
        type: MessageType.OPEN_STREAM,
        streamId: BigInt(wire.sid as number | bigint),
        label: wire.l as string | undefined,
      } satisfies OpenStreamMessage;

    case MessageType.CLOSE_STREAM:
      return {
        type: MessageType.CLOSE_STREAM,
        streamId: BigInt(wire.sid as number | bigint),
        errorCode: wire.ec as ErrorCode | undefined,
      } satisfies CloseStreamMessage;

    case MessageType.STREAM_DATA:
      return {
        type: MessageType.STREAM_DATA,
        streamId: BigInt(wire.sid as number | bigint),
        data: wire.d as Uint8Array,
        fin: wire.f as boolean | undefined,
      } satisfies StreamDataMessage;

    case MessageType.PING:
      return {
        type: MessageType.PING,
        sequence: BigInt(wire.seq as number | bigint),
        timestamp: BigInt(wire.ts as number | bigint),
      } satisfies PingMessage;

    case MessageType.PONG:
      return {
        type: MessageType.PONG,
        sequence: BigInt(wire.seq as number | bigint),
        timestamp: BigInt(wire.ts as number | bigint),
      } satisfies PongMessage;

    case MessageType.KNOCK:
      return {
        type: MessageType.KNOCK,
        inviteToken: wire.it as Uint8Array,
      } satisfies KnockMessage;

    case MessageType.KNOCK_RESPONSE:
      return {
        type: MessageType.KNOCK_RESPONSE,
        allowed: wire.a as boolean,
      } satisfies KnockResponseMessage;

    case MessageType.ERROR:
      return {
        type: MessageType.ERROR,
        errorCode: wire.ec as ErrorCode,
        reason: wire.r as string | undefined,
      } satisfies ErrorMessage;

    default:
      // Per SPECS 3.0: Unknown message types MUST cause ERR_VERSION_UNSUPPORTED
      throw new SNaP2PError(ErrorCode.ERR_VERSION_UNSUPPORTED, `Unknown message type: ${type}`);
  }
}
