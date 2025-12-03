/**
 * User Login API
 * POST /api/auth/login
 * 
 * Security features:
 * - Password verification with constant-time comparison
 * - Account locking after failed attempts
 * - MFA support
 * - Session management with secure cookies
 * - CSRF protection
 * - Login attempt logging
 */

import type { APIRoute } from 'astro';
import type { AuthResponse, User } from '../../../types/auth';
import { verifyPassword } from '../../../lib/crypto';
import { sanitizeInput, validateLogin, isAccountLocked, calculateLockTime } from '../../../lib/validation';
import { createSession, createSessionCookie } from '../../../lib/session';
import { getSecurityHeaders, logLoginAttempt, getRecentFailedAttempts, checkRateLimit } from '../../../lib/security';

export const prerender = false;

export const POST: APIRoute = async ({ request, locals }) => {
  let username = '';
  
  try {
    const db = locals.runtime.env.DB as D1Database;
    
    // Parse request body
    let body: { username?: string; password?: string };
    try {
      const text = await request.text();
      if (!text || text.trim() === '') {
        return new Response(
          JSON.stringify({
            success: false,
            message: 'Request body is empty'
          } as AuthResponse),
          {
            status: 400,
            headers: {
              'Content-Type': 'application/json',
              ...getSecurityHeaders()
            }
          }
        );
      }
      body = JSON.parse(text) as { username?: string; password?: string };
    } catch (parseError) {
      return new Response(
        JSON.stringify({
          success: false,
          message: 'Invalid JSON in request body'
        } as AuthResponse),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            ...getSecurityHeaders()
          }
        }
      );
    }
    
    // Validate input
    const validation = validateLogin(body);
    if (!validation.valid) {
      return new Response(
        JSON.stringify({
          success: false,
          message: validation.errors.join(', ')
        } as AuthResponse),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            ...getSecurityHeaders()
          }
        }
      );
    }
    
    // Sanitize username
    username = sanitizeInput(body.username || '');
    const password = body.password || '';
    
    // Get client IP
    const ipAddress = request.headers.get('cf-connecting-ip') || 
                      request.headers.get('x-forwarded-for') || 
                      'unknown';
    
    // Rate limiting: Check recent failed attempts
    const recentFailures = await getRecentFailedAttempts(db, username);
    if (!checkRateLimit(recentFailures)) {
      await logLoginAttempt(db, username, ipAddress, false, 'Rate limit exceeded');
      
      return new Response(
        JSON.stringify({
          success: false,
          message: 'Too many failed attempts. Please try again in 15 minutes.'
        } as AuthResponse),
        {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            ...getSecurityHeaders()
          }
        }
      );
    }
    
    // Get user (using prepared statement)
    const user = await db.prepare(`
      SELECT * FROM users WHERE username = ?
    `).bind(username).first<User>();
    
    if (!user) {
      await logLoginAttempt(db, username, ipAddress, false, 'User not found');
      
      return new Response(
        JSON.stringify({
          success: false,
          message: 'Invalid username or password'
        } as AuthResponse),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
            ...getSecurityHeaders()
          }
        }
      );
    }
    
    // Check if account is locked
    if (isAccountLocked(user.locked_until)) {
      await logLoginAttempt(db, username, ipAddress, false, 'Account locked');
      
      return new Response(
        JSON.stringify({
          success: false,
          message: 'Account is locked. Please try again later.'
        } as AuthResponse),
        {
          status: 403,
          headers: {
            'Content-Type': 'application/json',
            ...getSecurityHeaders()
          }
        }
      );
    }
    
    // Verify password
    const passwordValid = await verifyPassword(password, user.salt, user.password_hash);
    
    if (!passwordValid) {
      // Increment failed attempts
      const newFailedAttempts = user.failed_login_attempts + 1;
      const lockedUntil = calculateLockTime(newFailedAttempts);
      
      await db.prepare(`
        UPDATE users 
        SET failed_login_attempts = ?, locked_until = ?
        WHERE id = ?
      `).bind(newFailedAttempts, lockedUntil, user.id).run();
      
      await logLoginAttempt(db, username, ipAddress, false, 'Invalid password');
      
      return new Response(
        JSON.stringify({
          success: false,
          message: 'Invalid username or password'
        } as AuthResponse),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
            ...getSecurityHeaders()
          }
        }
      );
    }
    
    // Reset failed attempts on successful password verification
    await db.prepare(`
      UPDATE users 
      SET failed_login_attempts = 0, locked_until = NULL
      WHERE id = ?
    `).bind(user.id).run();
    
    // Check if MFA is enabled
    if (user.mfa_enabled) {
      // Store temporary session indicator (not a full session)
      const tempSessionId = crypto.randomUUID();
      
      await logLoginAttempt(db, username, ipAddress, true, 'Password verified, awaiting MFA');
      
      return new Response(
        JSON.stringify({
          success: true,
          message: 'MFA required',
          requiresMFA: true,
          sessionId: tempSessionId
        } as AuthResponse),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...getSecurityHeaders(),
            'Set-Cookie': `temp_session=${tempSessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=300`
          }
        }
      );
    }
    
    // Create session
    const { sessionId, csrfToken } = await createSession(db, user, request);
    
    await logLoginAttempt(db, username, ipAddress, true, 'Login successful');
    
    return new Response(
      JSON.stringify({
        success: true,
        message: 'Login successful',
        sessionId
      } as AuthResponse),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          ...getSecurityHeaders(),
          'Set-Cookie': createSessionCookie(sessionId)
        }
      }
    );
  } catch (error) {
    console.error('Login error:', error);
    
    if (username) {
      const ipAddress = request.headers.get('cf-connecting-ip') || 'unknown';
      const db = locals.runtime.env.DB as D1Database;
      await logLoginAttempt(db, username, ipAddress, false, 'Server error');
    }
    
    return new Response(
      JSON.stringify({
        success: false,
        message: 'An error occurred during login'
      } as AuthResponse),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          ...getSecurityHeaders()
        }
      }
    );
  }
};
