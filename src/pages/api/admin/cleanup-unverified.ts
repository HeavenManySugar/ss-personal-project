/**
 * Cleanup Unverified Accounts API
 * POST /api/admin/cleanup-unverified
 * 
 * Removes unverified accounts older than specified days
 * Should be called periodically (e.g., via cron job)
 */

import type { APIRoute } from 'astro';
import { getSecurityHeaders } from '../../../lib/security';

export const prerender = false;

export const POST: APIRoute = async ({ request, locals }) => {
  try {
    const db = locals.runtime.env.DB as D1Database;
    
    // Optional: Add authentication check here
    const authHeader = request.headers.get('Authorization');
    const expectedToken = locals.runtime.env.ADMIN_TOKEN as string;
    
    if (expectedToken && authHeader !== `Bearer ${expectedToken}`) {
      return new Response(
        JSON.stringify({ success: false, message: 'Unauthorized' }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
        }
      );
    }

    // Delete unverified accounts older than 7 days
    const deleteUsers = await db.prepare(`
      DELETE FROM users 
      WHERE email_verified = 0 
      AND created_at < datetime('now', '-7 days')
    `).run();

    // Delete expired verification tokens (older than 1 day)
    const deleteTokens = await db.prepare(`
      DELETE FROM email_verification_tokens 
      WHERE expires_at < datetime('now', '-1 day')
    `).run();

    return new Response(
      JSON.stringify({
        success: true,
        message: 'Cleanup completed',
        usersDeleted: deleteUsers.meta.changes || 0,
        tokensDeleted: deleteTokens.meta.changes || 0
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
      }
    );

  } catch (error) {
    console.error('Cleanup error:', error);
    return new Response(
      JSON.stringify({ success: false, message: 'Internal server error' }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...getSecurityHeaders() }
      }
    );
  }
};
