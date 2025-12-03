import type { APIRoute } from 'astro';
import { getProviderByName, generateOAuthState, storeOAuthState, buildAuthorizationUrl } from '../../../../lib/oauth';

/**
 * Initiate OAuth authorization flow
 * GET /api/oauth/{provider}/authorize
 */
export const GET: APIRoute = async ({ params, url, locals }) => {
  const { provider } = params;
  
  if (!provider) {
    return new Response('Provider not specified', { status: 400 });
  }

  try {
    const db = locals.runtime.env.DB as D1Database;
    
    // Get provider configuration
    const oauthProvider = await getProviderByName(db, provider);
    
    if (!oauthProvider) {
      return new Response('OAuth provider not found or disabled', { status: 404 });
    }

    // Generate state token for CSRF protection
    const state = await generateOAuthState();
    
    // Store state in database
    const redirectUri = `${url.origin}/api/oauth/${provider}/callback`;
    await storeOAuthState(db, state, oauthProvider.id, redirectUri);

    // Build authorization URL
    const authUrl = buildAuthorizationUrl(oauthProvider, state, redirectUri);

    // Redirect to OAuth provider
    return Response.redirect(authUrl, 302);
    
  } catch (error) {
    console.error('OAuth authorization error:', error);
    return new Response('OAuth authorization failed', { status: 500 });
  }
};
