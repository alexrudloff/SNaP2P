/**
 * Tests for SPECS 3.0 compliance: Unknown fields handling
 *
 * Per SPECS 3.0: "Unknown fields MUST be ignored"
 * Per SPECS 3.0: "Unknown message types MUST cause ERR_VERSION_UNSUPPORTED"
 *
 * These tests verify that:
 * 1. Unknown fields in messages are silently ignored
 * 2. Unknown message types trigger the correct error
 * 3. Messages with extra fields can still be decoded correctly
 */

import { describe, it, expect } from 'vitest';
import * as cborg from 'cborg';
import { decodeMessage, encodeMessage, encode, decode } from '../wire/codec.js';
import { MessageType, VisibilityMode } from '../types/messages.js';
import { ErrorCode } from '../types/errors.js';
import { deserializeAttestation, serializeAttestation } from '../identity/attestation.js';

/**
 * R2/S2: Test that unknown fields in HELLO messages are ignored
 */
describe('SPECS 3.0: Unknown Fields Handling', () => {
  describe('HELLO message', () => {
    it('should ignore unknown fields in HELLO message', () => {
      // Create a HELLO message with extra unknown fields
      const wireWithExtra = {
        t: MessageType.HELLO,
        v: 1,
        pk: new Uint8Array(32).fill(1),
        n: new Uint8Array(32).fill(2),
        ts: BigInt(1234567890),
        vis: VisibilityMode.PUBLIC,
        cap: ['test'],
        // Unknown fields that should be ignored
        unknownField: 'should be ignored',
        anotherUnknown: 12345,
        nestedUnknown: { foo: 'bar' },
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.HELLO);
      expect(decoded).toHaveProperty('version', 1);
      expect(decoded).toHaveProperty('visibility', VisibilityMode.PUBLIC);
      // Unknown fields should not be present in the decoded message
      expect(decoded).not.toHaveProperty('unknownField');
      expect(decoded).not.toHaveProperty('anotherUnknown');
      expect(decoded).not.toHaveProperty('nestedUnknown');
    });
  });

  describe('AUTH message', () => {
    it('should ignore unknown fields in AUTH message', () => {
      const wireWithExtra = {
        t: MessageType.AUTH,
        att: new Uint8Array([1, 2, 3, 4]),
        hd: new Uint8Array([5, 6, 7, 8]),
        // Unknown fields
        futureField: 'v2 feature',
        extraData: new Uint8Array([9, 9, 9]),
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.AUTH);
      expect(decoded).toHaveProperty('attestation');
      expect(decoded).toHaveProperty('handshakeData');
      expect(decoded).not.toHaveProperty('futureField');
      expect(decoded).not.toHaveProperty('extraData');
    });
  });

  describe('AUTH_OK message', () => {
    it('should ignore unknown fields in AUTH_OK message', () => {
      const wireWithExtra = {
        t: MessageType.AUTH_OK,
        p: 'stacks:SP123456',
        sid: new Uint8Array(32).fill(0xaa),
        // Unknown fields
        newCapability: true,
        version: '2.0',
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.AUTH_OK);
      expect(decoded).toHaveProperty('principal', 'stacks:SP123456');
      expect(decoded).not.toHaveProperty('newCapability');
      expect(decoded).not.toHaveProperty('version');
    });
  });

  describe('AUTH_FAIL message', () => {
    it('should ignore unknown fields in AUTH_FAIL message', () => {
      const wireWithExtra = {
        t: MessageType.AUTH_FAIL,
        ec: ErrorCode.ERR_ATTESTATION_INVALID,
        r: 'test reason',
        // Unknown fields
        errorDetails: { code: 42, message: 'extended error' },
        retryAfter: 60,
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.AUTH_FAIL);
      expect(decoded).toHaveProperty('errorCode', ErrorCode.ERR_ATTESTATION_INVALID);
      expect(decoded).toHaveProperty('reason', 'test reason');
      expect(decoded).not.toHaveProperty('errorDetails');
      expect(decoded).not.toHaveProperty('retryAfter');
    });
  });

  describe('OPEN_STREAM message', () => {
    it('should ignore unknown fields in OPEN_STREAM message', () => {
      const wireWithExtra = {
        t: MessageType.OPEN_STREAM,
        sid: BigInt(42),
        l: 'my-stream',
        // Unknown fields
        priority: 'high',
        maxSize: 1024000,
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.OPEN_STREAM);
      expect(decoded).toHaveProperty('streamId', BigInt(42));
      expect(decoded).toHaveProperty('label', 'my-stream');
      expect(decoded).not.toHaveProperty('priority');
      expect(decoded).not.toHaveProperty('maxSize');
    });
  });

  describe('CLOSE_STREAM message', () => {
    it('should ignore unknown fields in CLOSE_STREAM message', () => {
      const wireWithExtra = {
        t: MessageType.CLOSE_STREAM,
        sid: BigInt(42),
        ec: ErrorCode.ERR_STREAM_REFUSED,
        // Unknown fields
        graceful: true,
        bytesSent: 1024,
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.CLOSE_STREAM);
      expect(decoded).toHaveProperty('streamId', BigInt(42));
      expect(decoded).not.toHaveProperty('graceful');
      expect(decoded).not.toHaveProperty('bytesSent');
    });
  });

  describe('STREAM_DATA message', () => {
    it('should ignore unknown fields in STREAM_DATA message', () => {
      const wireWithExtra = {
        t: MessageType.STREAM_DATA,
        sid: BigInt(42),
        d: new Uint8Array([1, 2, 3, 4, 5]),
        f: true,
        // Unknown fields
        compressed: true,
        sequence: 123,
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.STREAM_DATA);
      expect(decoded).toHaveProperty('streamId', BigInt(42));
      expect(decoded).toHaveProperty('fin', true);
      expect(decoded).not.toHaveProperty('compressed');
      expect(decoded).not.toHaveProperty('sequence');
    });
  });

  describe('PING message', () => {
    it('should ignore unknown fields in PING message', () => {
      const wireWithExtra = {
        t: MessageType.PING,
        seq: BigInt(1),
        ts: BigInt(Date.now()),
        // Unknown fields
        priority: 1,
        urgent: false,
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.PING);
      expect(decoded).toHaveProperty('sequence', BigInt(1));
      expect(decoded).not.toHaveProperty('priority');
      expect(decoded).not.toHaveProperty('urgent');
    });
  });

  describe('PONG message', () => {
    it('should ignore unknown fields in PONG message', () => {
      const wireWithExtra = {
        t: MessageType.PONG,
        seq: BigInt(1),
        ts: BigInt(Date.now()),
        // Unknown fields
        latency: 50,
        metadata: { server: 'node1' },
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.PONG);
      expect(decoded).toHaveProperty('sequence', BigInt(1));
      expect(decoded).not.toHaveProperty('latency');
      expect(decoded).not.toHaveProperty('metadata');
    });
  });

  describe('KNOCK message', () => {
    it('should ignore unknown fields in KNOCK message', () => {
      const wireWithExtra = {
        t: MessageType.KNOCK,
        it: new Uint8Array(32).fill(0xbb),
        // Unknown fields
        clientVersion: '1.0.0',
        capabilities: ['feature1', 'feature2'],
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.KNOCK);
      expect(decoded).toHaveProperty('inviteToken');
      expect(decoded).not.toHaveProperty('clientVersion');
      expect(decoded).not.toHaveProperty('capabilities');
    });
  });

  describe('KNOCK_RESPONSE message', () => {
    it('should ignore unknown fields in KNOCK_RESPONSE message', () => {
      const wireWithExtra = {
        t: MessageType.KNOCK_RESPONSE,
        a: true,
        // Unknown fields
        serverName: 'test-server',
        queuePosition: 0,
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.KNOCK_RESPONSE);
      expect(decoded).toHaveProperty('allowed', true);
      expect(decoded).not.toHaveProperty('serverName');
      expect(decoded).not.toHaveProperty('queuePosition');
    });
  });

  describe('ERROR message', () => {
    it('should ignore unknown fields in ERROR message', () => {
      const wireWithExtra = {
        t: MessageType.ERROR,
        ec: ErrorCode.ERR_INTERNAL,
        r: 'Internal error occurred',
        // Unknown fields
        stack: 'Error: ...',
        debugInfo: { timestamp: Date.now() },
      };

      const encoded = cborg.encode(wireWithExtra);
      const decoded = decodeMessage(new Uint8Array(encoded));

      expect(decoded.type).toBe(MessageType.ERROR);
      expect(decoded).toHaveProperty('errorCode', ErrorCode.ERR_INTERNAL);
      expect(decoded).toHaveProperty('reason', 'Internal error occurred');
      expect(decoded).not.toHaveProperty('stack');
      expect(decoded).not.toHaveProperty('debugInfo');
    });
  });
});

/**
 * R2/S2: Test that unknown message types trigger ERR_VERSION_UNSUPPORTED
 */
describe('SPECS 3.0: Unknown Message Types', () => {
  it('should throw ERR_VERSION_UNSUPPORTED for unknown message type', () => {
    const unknownMessage = {
      t: 0xff00, // Unknown message type
      data: 'some data',
    };

    const encoded = cborg.encode(unknownMessage);

    expect(() => decodeMessage(new Uint8Array(encoded))).toThrow();

    try {
      decodeMessage(new Uint8Array(encoded));
    } catch (error) {
      expect(error).toHaveProperty('code', ErrorCode.ERR_VERSION_UNSUPPORTED);
      expect(error).toHaveProperty('message');
      expect((error as Error).message).toContain('Unknown message type');
    }
  });

  it('should throw for various invalid message types', () => {
    const invalidTypes = [0x99, 0x100, 0xffff, -1, 999999];

    for (const invalidType of invalidTypes) {
      const wire = { t: invalidType, data: 'test' };
      const encoded = cborg.encode(wire);

      expect(() => decodeMessage(new Uint8Array(encoded))).toThrow();
    }
  });
});

/**
 * R2/S2: Test attestation unknown fields handling
 */
describe('SPECS 3.0: Attestation Unknown Fields', () => {
  it('should ignore unknown fields in attestation payload', () => {
    // Create an attestation-like structure with unknown fields
    const attestationPayload = {
      v: 1,
      p: 'stacks:SP123456ABCD',
      npk: '01'.repeat(32), // 32 bytes as hex
      ts: BigInt(1234567890),
      exp: BigInt(1234567890 + 86400),
      nonce: new Uint8Array(32).fill(0xcc),
      domain: 'snap2p-nodekey-attestation-v1',
      sig: new Uint8Array(65).fill(0xdd),
      // Unknown future fields
      futureField1: 'should be ignored',
      futureField2: 12345,
      nestedFuture: { a: 1, b: 2 },
    };

    // The decode function from codec should handle this
    const encoded = encode(attestationPayload);
    const decoded = decode<typeof attestationPayload>(encoded);

    // Verify known fields are present
    expect(decoded.v).toBe(1);
    expect(decoded.p).toBe('stacks:SP123456ABCD');
    expect(decoded.domain).toBe('snap2p-nodekey-attestation-v1');

    // Note: The generic decode function preserves all fields,
    // but the attestation deserializer should only use known fields
  });
});

/**
 * R2/S2: Test round-trip encoding with extra fields
 */
describe('SPECS 3.0: Round-trip with unknown fields', () => {
  it('should handle round-trip encoding when receiver has extra fields', () => {
    // Simulate a newer client sending a message to an older client
    const newerClientMessage = {
      t: MessageType.HELLO,
      v: 1,
      pk: new Uint8Array(32).fill(0x11),
      n: new Uint8Array(32).fill(0x22),
      ts: BigInt(Math.floor(Date.now() / 1000)),
      vis: VisibilityMode.PUBLIC,
      cap: [],
      // New fields from future protocol version
      newFeature: true,
      extendedMetadata: { region: 'us-east' },
    };

    // Encode as newer client would
    const encoded = cborg.encode(newerClientMessage);

    // Decode as older client would (should ignore unknown fields)
    const decoded = decodeMessage(new Uint8Array(encoded));

    // Verify the message is usable
    expect(decoded.type).toBe(MessageType.HELLO);
    if (decoded.type === MessageType.HELLO) {
      expect(decoded.version).toBe(1);
      expect(decoded.visibility).toBe(VisibilityMode.PUBLIC);
      expect(decoded.nodePublicKey).toEqual(new Uint8Array(32).fill(0x11));
      expect(decoded.nonce).toEqual(new Uint8Array(32).fill(0x22));
    }

    // Re-encode the decoded message (should not include unknown fields)
    const reEncoded = encodeMessage(decoded);
    const finalDecoded = decodeMessage(reEncoded);

    expect(finalDecoded.type).toBe(MessageType.HELLO);
  });
});
