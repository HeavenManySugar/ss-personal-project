/**
 * Email Verification API
 * POST /api/auth/send-verification
 * 
 * Sends verification email to user
 */

import type { APIRoute } from 'astro';
import { sendVerificationEmail, generateVerificationCode, generateVerificationToken } from '../../../lib/email';
import { getSecurityHeaders } from '../../../lib/security';

export const prerender = false;

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const db = locals.runtime.env.DB as D1Database;
    
    const body = await request.json() as { userId: number; email: string; username: string };
    
    if (!body.userId || !body.email || !body.username) {
      return new Response(
        JSON.stringify({ success: false, message: 'Missing required fields' }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        }
      );
    }

    // Generate verification code and token
    const code = generateVerificationCode();
    const token = await generateVerificationToken();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minutes

    // Save to database
    await db.prepare(`
      INSERT INTO email_verification_tokens (user_id, token, code, expires_at)
      VALUES (?, ?, ?, ?)
    `).bind(body.userId, token, code, expiresAt).run();

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
      to: body.email,
      username: body.username,
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
        message: 'Verification email sent successfully',
        token // Return token for manual verification page
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
      }
    );

  } catch (error) {
    console.error('Send verification email error:', error);
    return new Response(
      JSON.stringify({ success: false, message: 'Internal server error' }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
      }
    );
  }
};
