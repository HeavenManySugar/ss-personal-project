import type { APIRoute } from 'astro';
import type { User } from '../../../../types/auth';
import {
  validateOAuthState,
  getProviderById,
  exchangeCodeForToken,
  fetchUserInfo,
  findUserByOAuthAccount,
  linkOAuthAccount,
} from '../../../../lib/oauth';
import { createSession } from '../../../../lib/session';

/**
 * Handle OAuth provider callback
 * GET /api/oauth/{provider}/callback
 */
export const GET: APIRoute = async ({ params, url, locals, cookies }) => {
  const { provider } = params;
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  // Check for OAuth errors
  if (error) {
    return Response.redirect(`/login?error=${encodeURIComponent(error)}`, 302);
  }

  if (!code || !state) {
    return Response.redirect('/login?error=missing_parameters', 302);
  }

  try {
    const db = locals.runtime.env.DB as D1Database;

    // Validate state token
    const stateRecord = await validateOAuthState(db, state);
    if (!stateRecord) {
      return Response.redirect('/login?error=invalid_state', 302);
    }

    // Get provider configuration
    const oauthProvider = await getProviderById(db, stateRecord.provider_id);
    if (!oauthProvider) {
      return Response.redirect('/login?error=provider_not_found', 302);
    }

    // Verify provider name matches
    if (oauthProvider.name !== provider) {
      return Response.redirect('/login?error=provider_mismatch', 302);
    }

    // Exchange code for access token
    const redirectUri = `${url.origin}/api/oauth/${provider}/callback`;
    const tokenData = await exchangeCodeForToken(oauthProvider, code, redirectUri);

    // Fetch user info from provider
    const userInfo = await fetchUserInfo(oauthProvider, tokenData.access_token);

    if (!userInfo.id) {
      return Response.redirect('/login?error=no_user_id', 302);
    }

    // Find existing user by OAuth account
    let userId = await findUserByOAuthAccount(db, oauthProvider.id, userInfo.id);

    if (userId) {
      // User exists, update OAuth account tokens
      await linkOAuthAccount(
        db,
        userId,
        oauthProvider.id,
        userInfo.id,
        userInfo,
        tokenData.access_token,
        tokenData.refresh_token,
        tokenData.expires_in
      );
    } else {
      // Check if user exists by email
      if (userInfo.email) {
        const existingUser = await db.prepare(
          'SELECT id FROM users WHERE email = ?'
        ).bind(userInfo.email).first<{ id: number }>();

        if (existingUser) {
          // Link OAuth account to existing user
          userId = existingUser.id;
          await linkOAuthAccount(
            db,
            userId,
            oauthProvider.id,
            userInfo.id,
            userInfo,
            tokenData.access_token,
            tokenData.refresh_token,
            tokenData.expires_in
          );
        } else {
          // Create new user
          const username = userInfo.username || userInfo.email.split('@')[0];
          const displayName = userInfo.name || username;

          const result = await db.prepare(
            `INSERT INTO users (username, email, password_hash, salt, email_verified, created_at)
             VALUES (?, ?, '', '', 1, CURRENT_TIMESTAMP)`
          ).bind(username, userInfo.email).run();

          userId = result.meta.last_row_id as number;

          // Link OAuth account
          await linkOAuthAccount(
            db,
            userId,
            oauthProvider.id,
            userInfo.id,
            userInfo,
            tokenData.access_token,
            tokenData.refresh_token,
            tokenData.expires_in
          );
        }
      } else {
        // No email provided by OAuth provider
        return Response.redirect('/login?error=no_email', 302);
      }
    }

    // Get user data for session
    const user = await db.prepare(
      'SELECT * FROM users WHERE id = ?'
    ).bind(userId).first<User>();

    if (!user) {
      return Response.redirect('/login?error=user_not_found', 302);
    }

    // Create a mock request for session creation
    const request = new Request(url.toString(), {
      headers: {
        'cf-connecting-ip': 'oauth-login',
        'user-agent': 'OAuth Login',
      },
    });

    // Create session
    const { sessionId, csrfToken } = await createSession(db, user, request);

    // Set session cookie
    cookies.set('sessionId', sessionId, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60, // 7 days
    });

    cookies.set('csrfToken', csrfToken, {
      path: '/',
      httpOnly: false,
      secure: true,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60,
    });

    // Redirect to dashboard
    return Response.redirect('/dashboard', 302);

  } catch (error) {
    console.error('OAuth callback error:', error);
    return Response.redirect('/login?error=oauth_failed', 302);
  }
};
