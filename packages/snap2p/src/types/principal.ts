/**
 * Principal represents a Stacks identity in the SNaP2P network.
 * Format: stacks:<address>
 */

export interface Principal {
  readonly scheme: 'stacks';
  readonly address: string;
}

const PRINCIPAL_REGEX = /^stacks:(S[A-Z0-9]{39,40})$/;

/**
 * Create a Principal from a Stacks address
 */
export function createPrincipal(address: string): Principal {
  if (!isValidStacksAddress(address)) {
    throw new Error(`Invalid Stacks address: ${address}`);
  }
  return { scheme: 'stacks', address };
}

/**
 * Parse a principal string (stacks:<address>)
 */
export function parsePrincipal(principal: string): Principal {
  const match = principal.match(PRINCIPAL_REGEX);
  if (!match) {
    throw new Error(`Invalid principal format: ${principal}`);
  }
  return { scheme: 'stacks', address: match[1] };
}

/**
 * Format a Principal to string
 */
export function formatPrincipal(principal: Principal): string {
  return `${principal.scheme}:${principal.address}`;
}

/**
 * Check if a string is a valid Stacks address
 */
export function isValidStacksAddress(address: string): boolean {
  // Stacks addresses start with S and are 40-41 characters
  // They use a modified base58check encoding
  return /^S[A-Z0-9]{39,40}$/.test(address);
}

/**
 * Compare two principals for equality
 */
export function principalsEqual(a: Principal, b: Principal): boolean {
  return a.scheme === b.scheme && a.address === b.address;
}
