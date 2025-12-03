/**
 * MFA Verification API
 * POST /api/auth/verify-mfa
 * 
 * Verifies TOTP code and creates session
 */

import type { APIRoute } from 'astro';
import type { AuthResponse, User } from '../../../types/auth';
import { verifyTOTP } from '../../../lib/mfa';
import { createSession, createSessionCookie } from '../../../lib/session';
import { getSecurityHeaders, logLoginAttempt } from '../../../lib/security';
import { sanitizeInput, isValidTOTPCode } from '../../../lib/validation';

export const prerender = false;

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const db = locals.runtime.env.DB as D1Database;
    
    // Parse request body
    let body: { username?: string; code?: string };
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
      body = JSON.parse(text) as { username?: string; code?: string };
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
    
    if (!body.username || !body.code) {
      return new Response(
        JSON.stringify({
          success: false,
          message: 'Username and MFA code are required'
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
    
    // Validate TOTP code format
    if (!isValidTOTPCode(body.code)) {
      return new Response(
        JSON.stringify({
          success: false,
          message: 'Invalid MFA code format'
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
    
    const username = sanitizeInput(body.username);
    const code = body.code;
    
    // Get user
    const user = await db.prepare(`
      SELECT * FROM users WHERE username = ? AND mfa_enabled = 1
    `).bind(username).first<User>();
    
    if (!user || !user.mfa_secret) {
      return new Response(
        JSON.stringify({
          success: false,
          message: 'Invalid request'
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
    
    // Verify TOTP code
    const valid = await verifyTOTP(user.mfa_secret, code);
    
    if (!valid) {
      const ipAddress = request.headers.get('cf-connecting-ip') || 'unknown';
      await logLoginAttempt(db, username, ipAddress, false, 'Invalid MFA code');
      
      return new Response(
        JSON.stringify({
          success: false,
          message: 'Invalid MFA code'
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
    
    // Create session
    const { sessionId } = await createSession(db, user, request);
    
    const ipAddress = request.headers.get('cf-connecting-ip') || 'unknown';
    await logLoginAttempt(db, username, ipAddress, true, 'MFA verified, login successful');
    
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
    console.error('MFA verification error:', error);
    
    return new Response(
      JSON.stringify({
        success: false,
        message: 'An error occurred during MFA verification'
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
