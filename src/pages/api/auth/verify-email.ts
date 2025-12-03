/**
 * Verify Email API
 * POST /api/auth/verify-email
 * 
 * Verifies email using token or code
 */

import type { APIRoute } from 'astro';
import { getSecurityHeaders } from '../../../lib/security';

export const prerender = false;

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const db = locals.runtime.env.DB as D1Database;
    
    const body = await request.json() as { token?: string; code?: string };
    
    if (!body.token && !body.code) {
      return new Response(
        JSON.stringify({ success: false, message: 'Token or code required' }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        }
      );
    }

    let verificationRecord;

    // Verify by token or code
    if (body.token) {
      verificationRecord = await db.prepare(`
        SELECT * FROM email_verification_tokens 
        WHERE token = ? AND verified = 0 AND expires_at > datetime('now')
      `).bind(body.token).first();
    } else if (body.code) {
      verificationRecord = await db.prepare(`
        SELECT * FROM email_verification_tokens 
        WHERE code = ? AND verified = 0 AND expires_at > datetime('now')
      `).bind(body.code).first();
    }

    if (!verificationRecord) {
      return new Response(
        JSON.stringify({ success: false, message: 'Invalid or expired verification code' }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        }
      );
    }

    // Mark as verified
    await db.prepare(`
      UPDATE email_verification_tokens SET verified = 1 WHERE id = ?
    `).bind(verificationRecord.id).run();

    await db.prepare(`
      UPDATE users SET email_verified = 1 WHERE id = ?
    `).bind(verificationRecord.user_id).run();

    return new Response(
      JSON.stringify({ 
        success: true, 
        message: 'Email verified successfully' 
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
      }
    );

  } catch (error) {
    console.error('Verify email error:', error);
    return new Response(
      JSON.stringify({ success: false, message: 'Internal server error' }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
      }
    );
  }
};
