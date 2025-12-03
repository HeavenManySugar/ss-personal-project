/**
 * Resend Verification Email API
 * POST /api/auth/resend-verification
 * 
 * Resends verification email to user
 */

import type { APIRoute } from 'astro';
import { sendVerificationEmail, generateVerificationCode, generateVerificationToken } from '../../../lib/email';
import { getSecurityHeaders } from '../../../lib/security';
import { sanitizeInput } from '../../../lib/validation';

export const prerender = false;

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const db = locals.runtime.env.DB as D1Database;
    
    const body = await request.json() as { email?: string; username?: string };
    
    if (!body.email && !body.username) {
      return new Response(
        JSON.stringify({ success: false, message: 'Email or username required' }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        }
      );
    }

    const identifier = sanitizeInput(body.email || body.username || '');

    // Find unverified user
    const user = await db.prepare(`
      SELECT id, username, email, email_verified FROM users 
      WHERE (email = ? OR username = ?) AND email_verified = 0
    `).bind(identifier, identifier).first() as {
      id: number;
      username: string;
      email: string;
      email_verified: number;
    } | null;

    if (!user) {
      return new Response(
        JSON.stringify({ 
          success: false, 
          message: 'User not found or already verified' 
        }),
        {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        }
      );
    }

    // Check rate limiting - only allow resend every 2 minutes
    const recentToken = await db.prepare(`
      SELECT created_at FROM email_verification_tokens 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 1
    `).bind(user.id).first() as { created_at: string } | null;

    if (recentToken) {
      const lastSent = new Date(recentToken.created_at);
      const now = new Date();
      const minutesSinceLastSend = (now.getTime() - lastSent.getTime()) / (1000 * 60);
      
      if (minutesSinceLastSend < 2) {
        return new Response(
          JSON.stringify({ 
            success: false, 
            message: `Please wait ${Math.ceil(2 - minutesSinceLastSend)} minute(s) before requesting another code` 
          }),
          {
            status: 429,
            headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
          }
        );
      }
    }

    // Generate new verification code and token
    const code = generateVerificationCode();
    const token = await generateVerificationToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minutes

    // Save to database
    await db.prepare(`
      INSERT INTO email_verification_tokens (user_id, token, code, expires_at)
      VALUES (?, ?, ?, ?)
    `).bind(user.id, token, code, expiresAt).run();

    // Get site URL from request
    const url = new URL(request.url);
    const siteUrl = `${url.protocol}//${url.host}`;

    // Email configuration (using Resend)
    const emailConfig = {
      apiKey: (locals.runtime.env.RESEND_API_KEY as string) || '',
      fromEmail: (locals.runtime.env.FROM_EMAIL as string) || 'onboarding@resend.dev',
      fromName: (locals.runtime.env.APP_NAME as string) || 'Your App Name'
    };

    // Send email
    const emailSent = await sendVerificationEmail(emailConfig, {
      to: user.email,
      username: user.username,
      code,
      token,
      siteUrl
    });

    if (!emailSent) {
      return new Response(
        JSON.stringify({ success: false, message: 'Failed to send verification email' }),
        {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        }
      );
    }

    return new Response(
      JSON.stringify({ 
        success: true, 
        message: 'Verification email sent successfully'
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
      }
    );

  } catch (error) {
    console.error('Resend verification email error:', error);
    return new Response(
      JSON.stringify({ success: false, message: 'Internal server error' }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
      }
    );
  }
};
