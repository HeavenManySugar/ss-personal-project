/**
 * Cryptographic utilities for secure password hashing
 * Uses PBKDF2 with SHA-256 and unique salts
 */

const ITERATIONS = 100000; // OWASP recommended minimum
const KEY_LENGTH = 32; // 256 bits
const SALT_LENGTH = 16; // 128 bits

/**
 * Generate a cryptographically secure random salt
 * @returns Hex-encoded salt string
 */
export function generateSalt(): string {
  const salt = new Uint8Array(SALT_LENGTH);
  crypto.getRandomValues(salt);
  return Array.from(salt)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Hash a password using PBKDF2-SHA256 with salt
 * @param password - Plain text password
 * @param salt - Hex-encoded salt
 * @returns Promise<string> - Hex-encoded hash
 */
export async function hashPassword(password: string, salt: string): Promise<string> {
  // Convert password to bytes
  const encoder = new TextEncoder();
  const passwordData = encoder.encode(password);
  
  // Convert salt from hex to bytes
  const saltData = new Uint8Array(
    salt.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
  );
  
  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordData,
    'PBKDF2',
    false,
    ['deriveBits']
  );
  
  // Derive key using PBKDF2
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltData,
      iterations: ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    KEY_LENGTH * 8
  );
  
  // Convert to hex string
  const hashArray = Array.from(new Uint8Array(derivedBits));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Verify a password against a stored hash
 * @param password - Plain text password to verify
 * @param salt - Hex-encoded salt
 * @param storedHash - Hex-encoded stored hash
 * @returns Promise<boolean> - True if password matches
 */
export async function verifyPassword(
  password: string,
  salt: string,
  storedHash: string
): Promise<boolean> {
  const hash = await hashPassword(password, salt);
  
  // Constant-time comparison to prevent timing attacks
  if (hash.length !== storedHash.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < hash.length; i++) {
    result |= hash.charCodeAt(i) ^ storedHash.charCodeAt(i);
  }
  
  return result === 0;
}

/**
 * Generate a cryptographically secure random token
 * @param length - Number of bytes (default: 32)
 * @returns Hex-encoded token
 */
export function generateToken(length: number = 32): string {
  const token = new Uint8Array(length);
  crypto.getRandomValues(token);
  return Array.from(token)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate a UUID v4
 * @returns UUID string
 */
export function generateUUID(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  
  // Set version (4) and variant bits
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  
  const hex = Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
