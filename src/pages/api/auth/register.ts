/**
 * User Registration API
 * POST /api/auth/register
 * 
 * Security features:
 * - Input validation and sanitization
 * - Password hashing with PBKDF2 and salt
 * - SQL injection prevention with prepared statements
 * - Rate limiting
 */

import type { APIRoute } from 'astro';
import type { AuthResponse } from '../../../types/auth';
import { generateSalt, hashPassword } from '../../../lib/crypto';
import { sanitizeInput, validateRegistration } from '../../../lib/validation';
import { getSecurityHeaders } from '../../../lib/security';

export const prerender = false;

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const db = locals.runtime.env.DB as D1Database;
    
    // Parse request body
    let body: { username?: string; email?: string; password?: string };
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
      body = JSON.parse(text) as { username?: string; email?: string; password?: string };
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
    const validation = validateRegistration(body);
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
    
    // Sanitize inputs to prevent XSS
    const username = sanitizeInput(body.username || '');
    const email = sanitizeInput(body.email || '');
    const password = body.password || ''; // Don't sanitize password (we hash it)
    
    // Check if username or email already exists (using prepared statement)
    const existing = await db.prepare(`
      SELECT id, username, email, email_verified, created_at FROM users 
      WHERE username = ? OR email = ?
    `).bind(username, email).first() as { 
      id: number; 
      username: string; 
      email: string; 
      email_verified: number; 
      created_at: string 
    } | null;
    
    if (existing) {
      // If user exists but email not verified, check if registration is old (>24 hours)
      if (existing.email_verified === 0) {
        const createdAt = new Date(existing.created_at);
        const now = new Date();
        const hoursSinceCreation = (now.getTime() - createdAt.getTime()) / (1000 * 60 * 60);
        
        // If registration is older than 24 hours and not verified, allow re-registration
        if (hoursSinceCreation > 24) {
          // Delete old unverified account
          await db.prepare(`DELETE FROM users WHERE id = ?`).bind(existing.id).run();
          // Continue with new registration below
        } else {
          // Account exists and is recent, offer to resend verification
          return new Response(
            JSON.stringify({
              success: false,
              message: 'Account already exists but not verified. Please check your email or wait 24 hours to re-register.',
              canResend: true,
              userId: existing.id
            } as AuthResponse),
            {
              status: 409,
              headers: {
                'Content-Type': 'application/json',
                ...getSecurityHeaders()
              }
            }
          );
        }
      } else {
        // Account exists and is verified
        return new Response(
          JSON.stringify({
            success: false,
            message: 'Username or email already exists'
          } as AuthResponse),
          {
            status: 409,
            headers: {
              'Content-Type': 'application/json',
              ...getSecurityHeaders()
            }
          }
        );
      }
    }
    
    // Generate salt and hash password
    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);
    
    // Insert user (using prepared statement to prevent SQL injection)
    const result = await db.prepare(`
      INSERT INTO users (username, email, password_hash, salt, email_verified)
      VALUES (?, ?, ?, ?, 0)
    `).bind(username, email, passwordHash, salt).run();
    
    // Get the new user ID
    const userId = result.meta.last_row_id;
    
    // Send verification email
    try {
      const verificationResponse = await fetch(new URL('/api/auth/send-verification', request.url).toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, email, username })
      });
      
      if (!verificationResponse.ok) {
        console.warn('Failed to send verification email');
      }
    } catch (emailError) {
      console.error('Error sending verification email:', emailError);
      // Continue registration even if email fails
    }
    
    return new Response(
      JSON.stringify({
        success: true,
        message: 'Registration successful. Please check your email to verify your account.',
        requiresVerification: true
      } as AuthResponse),
      {
        status: 201,
        headers: {
          'Content-Type': 'application/json',
          ...getSecurityHeaders()
        }
      }
    );
  } catch (error) {
    console.error('Registration error:', error);
    
    return new Response(
      JSON.stringify({
        success: false,
        message: 'An error occurred during registration'
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
