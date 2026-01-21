/**
 * Length-prefixed framing for SNaP2P messages.
 * Uses varint encoding for message length.
 */

/** Maximum message size (16 MB) */
const MAX_MESSAGE_SIZE = 16 * 1024 * 1024;

/**
 * Encode a varint (unsigned LEB128)
 */
export function encodeVarint(value: number): Uint8Array {
  if (value < 0) {
    throw new Error('Varint value must be non-negative');
  }

  const bytes: number[] = [];
  do {
    let byte = value & 0x7f;
    value >>>= 7;
    if (value !== 0) {
      byte |= 0x80;
    }
    bytes.push(byte);
  } while (value !== 0);

  return new Uint8Array(bytes);
}

/**
 * Decode a varint from buffer, returning value and bytes consumed
 */
export function decodeVarint(data: Uint8Array, offset: number = 0): { value: number; bytesRead: number } {
  let value = 0;
  let shift = 0;
  let bytesRead = 0;

  while (offset + bytesRead < data.length) {
    const byte = data[offset + bytesRead];
    value |= (byte & 0x7f) << shift;
    bytesRead++;

    if ((byte & 0x80) === 0) {
      return { value, bytesRead };
    }

    shift += 7;
    if (shift > 28) {
      throw new Error('Varint too large');
    }
  }

  throw new Error('Incomplete varint');
}

/**
 * Frame a message with length prefix
 */
export function frameMessage(data: Uint8Array): Uint8Array {
  if (data.length > MAX_MESSAGE_SIZE) {
    throw new Error(`Message too large: ${data.length} bytes (max: ${MAX_MESSAGE_SIZE})`);
  }

  const lengthPrefix = encodeVarint(data.length);
  const framed = new Uint8Array(lengthPrefix.length + data.length);
  framed.set(lengthPrefix, 0);
  framed.set(data, lengthPrefix.length);
  return framed;
}

/**
 * Result of parsing a framed message
 */
export interface ParseResult {
  /** The message data (without length prefix) */
  data: Uint8Array;
  /** Total bytes consumed (including length prefix) */
  bytesConsumed: number;
}

/**
 * Parse a framed message from buffer.
 * Returns null if buffer doesn't contain a complete message.
 */
export function parseFramedMessage(buffer: Uint8Array, offset: number = 0): ParseResult | null {
  if (buffer.length - offset < 1) {
    return null;
  }

  try {
    const { value: length, bytesRead } = decodeVarint(buffer, offset);

    if (length > MAX_MESSAGE_SIZE) {
      throw new Error(`Message too large: ${length} bytes (max: ${MAX_MESSAGE_SIZE})`);
    }

    const totalLength = bytesRead + length;
    if (buffer.length - offset < totalLength) {
      // Not enough data yet
      return null;
    }

    const data = buffer.slice(offset + bytesRead, offset + bytesRead + length);
    return { data, bytesConsumed: totalLength };
  } catch (e) {
    if (e instanceof Error && e.message === 'Incomplete varint') {
      return null;
    }
    throw e;
  }
}

/**
 * Buffer for accumulating incoming data and parsing frames
 */
export class FrameBuffer {
  private buffer: Uint8Array = new Uint8Array(0);

  /**
   * Append data to the buffer
   */
  append(data: Uint8Array): void {
    const newBuffer = new Uint8Array(this.buffer.length + data.length);
    newBuffer.set(this.buffer, 0);
    newBuffer.set(data, this.buffer.length);
    this.buffer = newBuffer;
  }

  /**
   * Try to read a complete frame from the buffer.
   * Returns the frame data if complete, null otherwise.
   */
  readFrame(): Uint8Array | null {
    const result = parseFramedMessage(this.buffer);
    if (result === null) {
      return null;
    }

    // Remove consumed bytes from buffer
    this.buffer = this.buffer.slice(result.bytesConsumed);
    return result.data;
  }

  /**
   * Get the current buffer size
   */
  get size(): number {
    return this.buffer.length;
  }

  /**
   * Clear the buffer
   */
  clear(): void {
    this.buffer = new Uint8Array(0);
  }
}
