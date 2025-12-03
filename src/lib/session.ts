/**
 * Session management utilities
 * Handles secure session creation, validation, and cleanup
 */

import type { Session, SessionData, User } from '../types/auth';
import { generateUUID, generateToken } from './crypto';

const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Create a new session for a user
 */
export async function createSession(
  db: D1Database,
  user: User,
  request: Request
): Promise<{ sessionId: string; csrfToken: string }> {
  const sessionId = generateUUID();
  const csrfToken = generateToken(32);
  const expiresAt = new Date(Date.now() + SESSION_DURATION).toISOString();
  
  // Get client info
  const ipAddress = request.headers.get('cf-connecting-ip') || 
                    request.headers.get('x-forwarded-for') || 
                    'unknown';
  const userAgent = request.headers.get('user-agent') || 'unknown';
  
  // Insert session (using prepared statement to prevent SQL injection)
  await db.prepare(`
    INSERT INTO sessions (id, user_id, expires_at, ip_address, user_agent, csrf_token)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(sessionId, user.id, expiresAt, ipAddress, userAgent, csrfToken).run();
  
  // Update last login
  await db.prepare(`
    UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
  `).bind(user.id).run();
  
  return { sessionId, csrfToken };
}

/**
 * Validate a session and return user data
 */
export async function validateSession(
  db: D1Database,
  sessionId: string
): Promise<SessionData | null> {
  // Get session with user data (using prepared statement)
  const result = await db.prepare(`
    SELECT 
      s.user_id,
      s.expires_at,
      s.csrf_token,
      u.username,
      u.email,
      u.mfa_enabled
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.id = ?
  `).bind(sessionId).first<{
    user_id: number;
    expires_at: string;
    csrf_token: string;
    username: string;
    email: string;
    mfa_enabled: number;
  }>();
  
  if (!result) {
    return null;
  }
  
  // Check if session expired
  if (new Date(result.expires_at) < new Date()) {
    await deleteSession(db, sessionId);
    return null;
  }
  
  return {
    userId: result.user_id,
    username: result.username,
    email: result.email,
    mfaEnabled: result.mfa_enabled === 1
  };
}

/**
 * Delete a session (logout)
 */
export async function deleteSession(db: D1Database, sessionId: string): Promise<void> {
  await db.prepare(`DELETE FROM sessions WHERE id = ?`).bind(sessionId).run();
}

/**
 * Delete all expired sessions (cleanup)
 */
export async function cleanupExpiredSessions(db: D1Database): Promise<void> {
  await db.prepare(`
    DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP
  `).run();
}

/**
 * Get session from cookie
 */
export function getSessionFromCookie(request: Request): string | null {
  const cookieHeader = request.headers.get('cookie');
  if (!cookieHeader) return null;
  
  const cookies = cookieHeader.split(';').map(c => c.trim());
  const sessionCookie = cookies.find(c => c.startsWith('session='));
  
  if (!sessionCookie) return null;
  
  return sessionCookie.split('=')[1];
}

/**
 * Create a secure session cookie
 */
export function createSessionCookie(sessionId: string, isDev = false): string {
  const expires = new Date(Date.now() + SESSION_DURATION);
  
  // Security flags:
  // - HttpOnly: Prevents JavaScript access (XSS protection)
  // - Secure: Only sent over HTTPS (omit in development)
  // - SameSite=Strict: CSRF protection
  const parts = [
    `session=${sessionId}`,
    `Path=/`,
    `Expires=${expires.toUTCString()}`,
    `HttpOnly`,
    `SameSite=Strict`
  ];
  
  // Only add Secure flag in production
  if (!isDev) {
    parts.push('Secure');
  }
  
  return parts.join('; ');
}

/**
 * Create a cookie to delete the session
 */
export function deleteSessionCookie(): string {
  return [
    `session=`,
    `Path=/`,
    `Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
    `HttpOnly`,
    `Secure`,
    `SameSite=Strict`
  ].join('; ');
}

/**
 * Validate CSRF token
 */
export async function validateCSRFToken(
  db: D1Database,
  sessionId: string,
  token: string
): Promise<boolean> {
  const result = await db.prepare(`
    SELECT csrf_token FROM sessions WHERE id = ?
  `).bind(sessionId).first<{ csrf_token: string }>();
  
  if (!result) return false;
  
  // Constant-time comparison
  return constantTimeCompare(token, result.csrf_token);
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
