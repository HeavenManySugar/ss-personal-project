/**
 * MFA Setup API
 * POST /api/auth/setup-mfa
 * 
 * Generates MFA secret and QR code for setup
 */

import type { APIRoute } from 'astro';
import type { AuthResponse, User } from '../../../types/auth';
import { generateMFASecret, generateQRCodeURL, generateQRCode, verifyTOTP } from '../../../lib/mfa';
import { getSessionFromCookie, validateSession } from '../../../lib/session';
import { getSecurityHeaders } from '../../../lib/security';

export const prerender = false;

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const db = locals.runtime.env.DB as D1Database;
    
    // Verify session
    const sessionId = getSessionFromCookie(request);
    if (!sessionId) {
      return new Response(
        JSON.stringify({
          success: false,
          message: 'Not authenticated'
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
    
    const session = await validateSession(db, sessionId);
    if (!session) {
      return new Response(
        JSON.stringify({
          success: false,
          message: 'Invalid session'
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
    
    const body = await request.json() as { action?: string; code?: string };
    
    // Generate MFA secret
    if (body.action === 'generate') {
      const secret = generateMFASecret();
      const qrCodeUrl = generateQRCodeURL(secret, session.username);
      const qrCodeImage = generateQRCode(qrCodeUrl);
      
      // Store secret temporarily (not enabled yet)
      await db.prepare(`
        UPDATE users SET mfa_secret = ? WHERE id = ?
      `).bind(secret, session.userId).run();
      
      return new Response(
        JSON.stringify({
          success: true,
          message: 'MFA secret generated',
          mfaSetup: {
            secret,
            qrCodeUrl: qrCodeImage,
            manualEntryKey: secret
          }
        } as AuthResponse),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...getSecurityHeaders()
          }
        }
      );
    }
    
    // Verify and enable MFA
    if (body.action === 'verify' && body.code) {
      const user = await db.prepare(`
        SELECT * FROM users WHERE id = ?
      `).bind(session.userId).first<User>();
      
      if (!user || !user.mfa_secret) {
        return new Response(
          JSON.stringify({
            success: false,
            message: 'MFA not initialized'
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
      
      // Verify the code
      const valid = await verifyTOTP(user.mfa_secret, body.code);
      
      if (!valid) {
        return new Response(
          JSON.stringify({
            success: false,
            message: 'Invalid MFA code'
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
      
      // Enable MFA
      await db.prepare(`
        UPDATE users SET mfa_enabled = 1 WHERE id = ?
      `).bind(session.userId).run();
      
      return new Response(
        JSON.stringify({
          success: true,
          message: 'MFA enabled successfully'
        } as AuthResponse),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...getSecurityHeaders()
          }
        }
      );
    }
    
    // Disable MFA
    if (body.action === 'disable') {
      await db.prepare(`
        UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?
      `).bind(session.userId).run();
      
      return new Response(
        JSON.stringify({
          success: true,
          message: 'MFA disabled'
        } as AuthResponse),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...getSecurityHeaders()
          }
        }
      );
    }
    
    return new Response(
      JSON.stringify({
        success: false,
        message: 'Invalid action'
      } as AuthResponse),
      {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          ...getSecurityHeaders()
        }
      }
    );
  } catch (error) {
    console.error('MFA setup error:', error);
    
    return new Response(
      JSON.stringify({
        success: false,
        message: 'An error occurred during MFA setup'
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
