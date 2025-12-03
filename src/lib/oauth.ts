/**
 * OAuth Authentication Library
 * Handles OAuth flow, token management, and provider integration
 */

export interface OAuthProvider {
  id: number;
  name: string;
  display_name: string;
  client_id: string;
  client_secret: string;
  authorization_url: string;
  token_url: string;
  user_info_url: string;
  scope: string;
  enabled: number;
  icon_url?: string;
}

export interface OAuthState {
  state: string;
  provider_id: number;
  redirect_uri?: string;
  expires_at: string;
}

export interface OAuthUserInfo {
  id: string;
  email?: string;
  name?: string;
  username?: string;
  avatar_url?: string;
}

/**
 * Generate a secure random state token for CSRF protection
 */
export async function generateOAuthState(): Promise<string> {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Store OAuth state in database
 */
export async function storeOAuthState(
  db: D1Database,
  state: string,
  providerId: number,
  redirectUri?: string
): Promise<void> {
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
  
  await db.prepare(
    `INSERT INTO oauth_states (state, provider_id, redirect_uri, expires_at)
     VALUES (?, ?, ?, ?)`
  ).bind(state, providerId, redirectUri || null, expiresAt.toISOString()).run();
}

/**
 * Validate OAuth state token
 */
export async function validateOAuthState(
  db: D1Database,
  state: string
): Promise<OAuthState | null> {
  const result = await db.prepare(
    `SELECT state, provider_id, redirect_uri, expires_at
     FROM oauth_states
     WHERE state = ? AND expires_at > datetime('now')`
  ).bind(state).first<OAuthState>();

  if (result) {
    // Delete used state
    await db.prepare('DELETE FROM oauth_states WHERE state = ?').bind(state).run();
  }

  return result;
}

/**
 * Get enabled OAuth providers
 */
export async function getEnabledProviders(db: D1Database): Promise<OAuthProvider[]> {
  const { results } = await db.prepare(
    `SELECT * FROM oauth_providers WHERE enabled = 1 ORDER BY display_name`
  ).all<OAuthProvider>();
  
  return results || [];
}

/**
 * Get OAuth provider by ID
 */
export async function getProviderById(
  db: D1Database,
  providerId: number
): Promise<OAuthProvider | null> {
  return await db.prepare(
    'SELECT * FROM oauth_providers WHERE id = ?'
  ).bind(providerId).first<OAuthProvider>();
}

/**
 * Get OAuth provider by name
 */
export async function getProviderByName(
  db: D1Database,
  name: string
): Promise<OAuthProvider | null> {
  return await db.prepare(
    'SELECT * FROM oauth_providers WHERE name = ? AND enabled = 1'
  ).bind(name).first<OAuthProvider>();
}

/**
 * Build authorization URL
 */
export function buildAuthorizationUrl(
  provider: OAuthProvider,
  state: string,
  redirectUri: string
): string {
  const params = new URLSearchParams({
    client_id: provider.client_id,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: provider.scope,
    state: state,
  });

  return `${provider.authorization_url}?${params.toString()}`;
}

/**
 * Exchange authorization code for access token
 */
export async function exchangeCodeForToken(
  provider: OAuthProvider,
  code: string,
  redirectUri: string
): Promise<{ access_token: string; refresh_token?: string; expires_in?: number }> {
  const params = new URLSearchParams({
    client_id: provider.client_id,
    client_secret: provider.client_secret,
    code: code,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
  });

  const response = await fetch(provider.token_url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Token exchange failed: ${error}`);
  }

  return await response.json();
}

/**
 * Fetch user info from OAuth provider
 */
export async function fetchUserInfo(
  provider: OAuthProvider,
  accessToken: string
): Promise<OAuthUserInfo> {
  const response = await fetch(provider.user_info_url, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch user info');
  }

  const data = await response.json();

  // Normalize user info based on provider
  return normalizeUserInfo(provider.name, data);
}

/**
 * Normalize user info from different providers
 */
function normalizeUserInfo(providerName: string, data: any): OAuthUserInfo {
  switch (providerName) {
    case 'google':
      return {
        id: data.id,
        email: data.email,
        name: data.name,
        username: data.email?.split('@')[0],
        avatar_url: data.picture,
      };
    
    case 'github':
      return {
        id: String(data.id),
        email: data.email,
        name: data.name || data.login,
        username: data.login,
        avatar_url: data.avatar_url,
      };
    
    case 'microsoft':
      return {
        id: data.id,
        email: data.mail || data.userPrincipalName,
        name: data.displayName,
        username: data.userPrincipalName?.split('@')[0],
        avatar_url: undefined,
      };
    
    default:
      return {
        id: data.id || data.sub,
        email: data.email,
        name: data.name,
        username: data.username || data.login || data.email?.split('@')[0],
      };
  }
}

/**
 * Link OAuth account to existing user
 */
export async function linkOAuthAccount(
  db: D1Database,
  userId: number,
  providerId: number,
  providerUserId: string,
  userInfo: OAuthUserInfo,
  accessToken: string,
  refreshToken?: string,
  expiresIn?: number
): Promise<void> {
  const expiresAt = expiresIn 
    ? new Date(Date.now() + expiresIn * 1000).toISOString()
    : null;

  await db.prepare(
    `INSERT INTO oauth_accounts 
     (user_id, provider_id, provider_user_id, provider_email, provider_username, access_token, refresh_token, token_expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(provider_id, provider_user_id) 
     DO UPDATE SET access_token = ?, refresh_token = ?, token_expires_at = ?, updated_at = CURRENT_TIMESTAMP`
  ).bind(
    userId, providerId, providerUserId, userInfo.email || null, userInfo.username || null,
    accessToken, refreshToken || null, expiresAt,
    accessToken, refreshToken || null, expiresAt
  ).run();
}

/**
 * Find user by OAuth provider account
 */
export async function findUserByOAuthAccount(
  db: D1Database,
  providerId: number,
  providerUserId: string
): Promise<number | null> {
  const result = await db.prepare(
    'SELECT user_id FROM oauth_accounts WHERE provider_id = ? AND provider_user_id = ?'
  ).bind(providerId, providerUserId).first<{ user_id: number }>();

  return result?.user_id || null;
}

/**
 * Get user's OAuth accounts
 */
export async function getUserOAuthAccounts(
  db: D1Database,
  userId: number
): Promise<Array<{ provider_name: string; provider_display_name: string; provider_email: string }>> {
  const { results } = await db.prepare(
    `SELECT p.name as provider_name, p.display_name as provider_display_name, oa.provider_email
     FROM oauth_accounts oa
     JOIN oauth_providers p ON oa.provider_id = p.id
     WHERE oa.user_id = ?`
  ).bind(userId).all<{ provider_name: string; provider_display_name: string; provider_email: string }>();

  return results || [];
}

/**
 * Unlink OAuth account
 */
export async function unlinkOAuthAccount(
  db: D1Database,
  userId: number,
  providerId: number
): Promise<void> {
  await db.prepare(
    'DELETE FROM oauth_accounts WHERE user_id = ? AND provider_id = ?'
  ).bind(userId, providerId).run();
}

/**
 * Clean up expired OAuth states
 */
export async function cleanupExpiredStates(db: D1Database): Promise<void> {
  await db.prepare(
    "DELETE FROM oauth_states WHERE expires_at < datetime('now')"
  ).run();
}
