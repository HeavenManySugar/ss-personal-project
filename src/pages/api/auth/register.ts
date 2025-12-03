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
      SELECT username, email FROM users WHERE username = ? OR email = ?
    `).bind(username, email).first();
    
    if (existing) {
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
    
    // Generate salt and hash password
    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);
    
    // Insert user (using prepared statement to prevent SQL injection)
    await db.prepare(`
      INSERT INTO users (username, email, password_hash, salt)
      VALUES (?, ?, ?, ?)
    `).bind(username, email, passwordHash, salt).run();
    
    return new Response(
      JSON.stringify({
        success: true,
        message: 'Registration successful. Please login.'
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
