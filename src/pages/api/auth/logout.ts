/**
 * Logout API
 * POST /api/auth/logout
 * 
 * Destroys session and clears cookie
 */

import type { APIRoute } from 'astro';
import type { AuthResponse } from '../../../types/auth';
import { getSessionFromCookie, deleteSession, deleteSessionCookie } from '../../../lib/session';
import { getSecurityHeaders } from '../../../lib/security';

export const prerender = false;

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const db = locals.runtime.env.DB as D1Database;
    
    // Get session from cookie
    const sessionId = getSessionFromCookie(request);
    
    if (sessionId) {
      // Delete session from database
      await deleteSession(db, sessionId);
    }
    
    return new Response(
      JSON.stringify({
        success: true,
        message: 'Logged out successfully'
      } as AuthResponse),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          ...getSecurityHeaders(),
          'Set-Cookie': deleteSessionCookie()
        }
      }
    );
  } catch (error) {
    console.error('Logout error:', error);
    
    return new Response(
      JSON.stringify({
        success: false,
        message: 'An error occurred during logout'
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
