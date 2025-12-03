/**
 * Additional security utilities
 */

/**
 * Log a login attempt
 */
export async function logLoginAttempt(
  db: D1Database,
  username: string,
  ipAddress: string,
  success: boolean,
  failureReason?: string
): Promise<void> {
  await db.prepare(`
    INSERT INTO login_attempts (username, ip_address, success, failure_reason)
    VALUES (?, ?, ?, ?)
  `).bind(username, ipAddress, success ? 1 : 0, failureReason || null).run();
}

/**
 * Get recent failed login attempts for rate limiting
 */
export async function getRecentFailedAttempts(
  db: D1Database,
  username: string,
  minutes: number = 15
): Promise<number> {
  const cutoff = new Date(Date.now() - minutes * 60 * 1000).toISOString();
  
  const result = await db.prepare(`
    SELECT COUNT(*) as count
    FROM login_attempts
    WHERE username = ? AND success = 0 AND attempted_at > ?
  `).bind(username, cutoff).first<{ count: number }>();
  
  return result?.count || 0;
}

/**
 * Generate Content Security Policy header
 */
export function generateCSPHeader(): string {
  return [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'", // Astro needs unsafe-inline
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; ');
}

/**
 * Generate security headers for responses
 */
export function getSecurityHeaders(): Record<string, string> {
  return {
    'Content-Security-Policy': generateCSPHeader(),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
  };
}

/**
 * Rate limiting check
 */
export function checkRateLimit(attempts: number, maxAttempts: number = 5): boolean {
  return attempts < maxAttempts;
}
