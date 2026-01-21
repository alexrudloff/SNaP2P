/**
 * Error codes for SNaP2P protocol.
 * Based on SPECS.md error handling requirements.
 */

export enum ErrorCode {
  /** No error */
  OK = 0,

  /** Generic/unspecified error */
  ERR_UNKNOWN = 1,

  /** Protocol version not supported */
  ERR_VERSION_UNSUPPORTED = 2,

  /** Authentication failed */
  ERR_AUTH_FAILED = 3,

  /** Peer not on allowlist (Private/Stealth mode) */
  ERR_NOT_ALLOWED = 4,

  /** Invalid invite token (Stealth mode) */
  ERR_INVALID_TOKEN = 5,

  /** Attestation verification failed */
  ERR_ATTESTATION_INVALID = 6,

  /** Attestation expired */
  ERR_ATTESTATION_EXPIRED = 7,

  /** Handshake failed */
  ERR_HANDSHAKE_FAILED = 8,

  /** Stream ID already in use */
  ERR_STREAM_ID_IN_USE = 9,

  /** Stream not found */
  ERR_STREAM_NOT_FOUND = 10,

  /** Stream closed */
  ERR_STREAM_CLOSED = 11,

  /** Connection closed */
  ERR_CONNECTION_CLOSED = 12,

  /** Timeout */
  ERR_TIMEOUT = 13,

  /** Message too large */
  ERR_MESSAGE_TOO_LARGE = 14,

  /** Invalid message format */
  ERR_INVALID_MESSAGE = 15,

  /** Resource exhausted */
  ERR_RESOURCE_EXHAUSTED = 16,

  /** Internal error */
  ERR_INTERNAL = 17,
}

/**
 * Get human-readable description for error code
 */
export function getErrorMessage(code: ErrorCode): string {
  const messages: Record<ErrorCode, string> = {
    [ErrorCode.OK]: 'OK',
    [ErrorCode.ERR_UNKNOWN]: 'Unknown error',
    [ErrorCode.ERR_VERSION_UNSUPPORTED]: 'Protocol version not supported',
    [ErrorCode.ERR_AUTH_FAILED]: 'Authentication failed',
    [ErrorCode.ERR_NOT_ALLOWED]: 'Peer not allowed',
    [ErrorCode.ERR_INVALID_TOKEN]: 'Invalid invite token',
    [ErrorCode.ERR_ATTESTATION_INVALID]: 'Attestation verification failed',
    [ErrorCode.ERR_ATTESTATION_EXPIRED]: 'Attestation expired',
    [ErrorCode.ERR_HANDSHAKE_FAILED]: 'Handshake failed',
    [ErrorCode.ERR_STREAM_ID_IN_USE]: 'Stream ID already in use',
    [ErrorCode.ERR_STREAM_NOT_FOUND]: 'Stream not found',
    [ErrorCode.ERR_STREAM_CLOSED]: 'Stream closed',
    [ErrorCode.ERR_CONNECTION_CLOSED]: 'Connection closed',
    [ErrorCode.ERR_TIMEOUT]: 'Operation timed out',
    [ErrorCode.ERR_MESSAGE_TOO_LARGE]: 'Message too large',
    [ErrorCode.ERR_INVALID_MESSAGE]: 'Invalid message format',
    [ErrorCode.ERR_RESOURCE_EXHAUSTED]: 'Resource exhausted',
    [ErrorCode.ERR_INTERNAL]: 'Internal error',
  };
  return messages[code] ?? 'Unknown error';
}

/**
 * Custom error class for SNaP2P errors
 */
export class SNaP2PError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message?: string
  ) {
    super(message ?? getErrorMessage(code));
    this.name = 'SNaP2PError';
  }
}
