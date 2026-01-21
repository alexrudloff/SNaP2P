/**
 * Locator identifies how to reach a peer on the network.
 * Can be a direct address or include additional metadata.
 */

export interface Locator {
  /** Transport protocol */
  readonly transport: 'tcp' | 'quic';
  /** Host address (IP or hostname) */
  readonly host: string;
  /** Port number */
  readonly port: number;
  /** Optional node public key (hex-encoded ed25519) */
  readonly nodePublicKey?: string;
}

/**
 * Parse a locator string (host:port or transport://host:port)
 */
export function parseLocator(locator: string): Locator {
  // Check for explicit transport prefix
  const transportMatch = locator.match(/^(tcp|quic):\/\/(.+)$/);
  const transport = transportMatch ? (transportMatch[1] as 'tcp' | 'quic') : 'tcp';
  const addressPart = transportMatch ? transportMatch[2] : locator;

  // Parse host:port
  const match = addressPart.match(/^([^:]+):(\d+)$/);
  if (!match) {
    throw new Error(`Invalid locator format: ${locator}`);
  }

  const host = match[1];
  const port = parseInt(match[2], 10);

  if (port < 1 || port > 65535) {
    throw new Error(`Invalid port number: ${port}`);
  }

  return { transport, host, port };
}

/**
 * Format a Locator to string
 */
export function formatLocator(locator: Locator): string {
  if (locator.transport === 'tcp') {
    return `${locator.host}:${locator.port}`;
  }
  return `${locator.transport}://${locator.host}:${locator.port}`;
}

/**
 * Create a Locator with optional parameters
 */
export function createLocator(
  host: string,
  port: number,
  options?: { transport?: 'tcp' | 'quic'; nodePublicKey?: string }
): Locator {
  if (port < 1 || port > 65535) {
    throw new Error(`Invalid port number: ${port}`);
  }
  return {
    transport: options?.transport ?? 'tcp',
    host,
    port,
    nodePublicKey: options?.nodePublicKey,
  };
}
