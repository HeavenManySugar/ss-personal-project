/**
 * Multi-Factor Authentication (MFA) using TOTP (Time-based One-Time Password)
 * Implements RFC 6238 - TOTP: Time-Based One-Time Password Algorithm
 */

const TOTP_PERIOD = 30; // 30 seconds
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1; // Allow 1 step before and after for clock drift

/**
 * Generate a random base32 secret for TOTP
 * @returns Base32-encoded secret
 */
export function generateMFASecret(): string {
  const bytes = new Uint8Array(20); // 160 bits
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

/**
 * Generate a TOTP code from a secret
 * @param secret - Base32-encoded secret
 * @param timestamp - Unix timestamp (default: current time)
 * @returns 6-digit TOTP code
 */
export async function generateTOTP(secret: string, timestamp?: number): Promise<string> {
  const time = Math.floor((timestamp || Date.now()) / 1000 / TOTP_PERIOD);
  const secretBytes = base32Decode(secret);
  
  // Create time buffer (8 bytes, big-endian)
  const timeBuffer = new ArrayBuffer(8);
  const timeView = new DataView(timeBuffer);
  timeView.setUint32(4, time, false); // Big-endian
  
  // Import secret as HMAC key
  const key = await crypto.subtle.importKey(
    'raw',
    secretBytes as BufferSource,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  
  // Generate HMAC
  const hmac = await crypto.subtle.sign('HMAC', key, timeBuffer);
  const hmacArray = new Uint8Array(hmac);
  
  // Dynamic truncation (RFC 4226)
  const offset = hmacArray[hmacArray.length - 1] & 0x0f;
  const code =
    ((hmacArray[offset] & 0x7f) << 24) |
    ((hmacArray[offset + 1] & 0xff) << 16) |
    ((hmacArray[offset + 2] & 0xff) << 8) |
    (hmacArray[offset + 3] & 0xff);
  
  // Get last 6 digits
  const otp = (code % Math.pow(10, TOTP_DIGITS)).toString().padStart(TOTP_DIGITS, '0');
  return otp;
}

/**
 * Verify a TOTP code against a secret
 * @param secret - Base32-encoded secret
 * @param code - 6-digit TOTP code to verify
 * @returns Promise<boolean> - True if code is valid
 */
export async function verifyTOTP(secret: string, code: string): Promise<boolean> {
  if (!/^\d{6}$/.test(code)) {
    return false;
  }
  
  const now = Date.now();
  
  // Check current time window and adjacent windows (for clock drift)
  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
    const timestamp = now + (i * TOTP_PERIOD * 1000);
    const validCode = await generateTOTP(secret, timestamp);
    
    if (constantTimeCompare(code, validCode)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Generate a QR code URL for Google Authenticator
 * @param secret - Base32-encoded secret
 * @param username - User's username
 * @param issuer - Application name
 * @returns otpauth:// URL
 */
export function generateQRCodeURL(
  secret: string,
  username: string,
  issuer: string = 'SecureAuthSystem'
): string {
  const label = encodeURIComponent(`${issuer}:${username}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: TOTP_DIGITS.toString(),
    period: TOTP_PERIOD.toString()
  });
  
  return `otpauth://totp/${label}?${params.toString()}`;
}

/**
 * Generate a QR code data URL for display
 * @param otpauthUrl - otpauth:// URL
 * @returns Data URL for QR code image
 */
export function generateQRCode(otpauthUrl: string): string {
  // Use a public QR code API (in production, generate locally)
  const encodedUrl = encodeURIComponent(otpauthUrl);
  return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodedUrl}`;
}

/**
 * Base32 encoding (RFC 4648)
 */
function base32Encode(buffer: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  
  return output;
}

/**
 * Base32 decoding (RFC 4648)
 */
function base32Decode(input: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  input = input.toUpperCase().replace(/=+$/, '');
  
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor((input.length * 5) / 8));
  
  for (let i = 0; i < input.length; i++) {
    const idx = alphabet.indexOf(input[i]);
    if (idx === -1) throw new Error('Invalid base32 character');
    
    value = (value << 5) | idx;
    bits += 5;
    
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  
  return output;
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}
