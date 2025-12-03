/**
 * Send MFA Code via Email API
 * POST /api/auth/send-mfa-email
 * 
 * Sends MFA verification code via email as an alternative to TOTP
 */

import type { APIRoute } from 'astro';
import { generateVerificationCode, generateVerificationToken } from '../../../lib/email';
import { getSecurityHeaders } from '../../../lib/security';
import { sanitizeInput } from '../../../lib/validation';

export const prerender = false;

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const db = locals.runtime.env.DB as D1Database;
    
    const body = await request.json() as { username?: string };
    
    if (!body.username) {
      return new Response(
        JSON.stringify({ success: false, message: 'Username required' }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        }
      );
    }

    const username = sanitizeInput(body.username);

    // Get user
    const user = await db.prepare(`
      SELECT id, username, email, mfa_enabled FROM users 
      WHERE username = ? AND mfa_enabled = 1
    `).bind(username).first() as {
      id: number;
      username: string;
      email: string;
      mfa_enabled: number;
    } | null;

    if (!user) {
      return new Response(
        JSON.stringify({ success: false, message: 'Invalid request' }),
        {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        }
      );
    }

    // Check rate limiting - only allow sending every 2 minutes
    const recentToken = await db.prepare(`
      SELECT created_at FROM mfa_email_tokens 
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

    // Generate MFA code
    const code = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 minutes

    // Save to database
    await db.prepare(`
      INSERT INTO mfa_email_tokens (user_id, code, expires_at)
      VALUES (?, ?, ?)
    `).bind(user.id, code, expiresAt).run();

    // Send email via Resend
    const apiKey = locals.runtime.env.RESEND_API_KEY as string;
    const fromEmail = (locals.runtime.env.FROM_EMAIL as string) || 'onboarding@resend.dev';

    const emailHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #2196F3; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
    .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
    .code-box { background: white; border: 2px dashed #2196F3; padding: 20px; text-align: center; margin: 20px 0; border-radius: 4px; }
    .code { font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #2196F3; }
    .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔐 MFA Verification Code</h1>
    </div>
    <div class="content">
      <p>Hi <strong>${user.username}</strong>,</p>
      <p>Your login verification code is:</p>
      
      <div class="code-box">
        <div class="code">${code}</div>
      </div>
      
      <p>This code will expire in 10 minutes.</p>
      <p>If you didn't request this code, please ignore this email and secure your account.</p>
    </div>
    <div class="footer">
      <p>This is an automated email. Please do not reply.</p>
    </div>
  </div>
</body>
</html>
    `.trim();

    const emailText = `
MFA Verification Code

Hi ${user.username},

Your login verification code is: ${code}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email and secure your account.

---
This is an automated email. Please do not reply.
    `.trim();

    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        from: `${(locals.runtime.env.APP_NAME as string) || 'Your App Name'} <${fromEmail}>`,
        to: [user.email],
        subject: 'Your Login Verification Code',
        text: emailText,
        html: emailHtml
      })
    });

    if (!response.ok) {
      console.error('Failed to send MFA email:', await response.text());
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
        message: 'Verification code sent to your email',
        email: user.email.replace(/(.{2})(.*)(@.*)/, '$1***$3') // Mask email
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
      }
    );

  } catch (error) {
    console.error('Send MFA email error:', error);
    return new Response(
      JSON.stringify({ success: false, message: 'Internal server error' }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
      }
    );
  }
};
