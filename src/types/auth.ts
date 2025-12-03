/**
 * Type definitions for the authentication system
 */

export interface User {
  id: number;
  username: string;
  email: string;
  password_hash: string;
  salt: string;
  mfa_secret: string | null;
  mfa_enabled: number;
  created_at: string;
  last_login: string | null;
  failed_login_attempts: number;
  locked_until: string | null;
}

export interface Session {
  id: string;
  user_id: number;
  created_at: string;
  expires_at: string;
  ip_address: string | null;
  user_agent: string | null;
  csrf_token: string;
}

export interface LoginAttempt {
  id: number;
  username: string;
  ip_address: string | null;
  success: number;
  attempted_at: string;
  failure_reason: string | null;
}

export interface RegistrationData {
  username: string;
  email: string;
  password: string;
}

export interface LoginData {
  username: string;
  password: string;
  mfaCode?: string;
}

export interface SessionData {
  userId: number;
  username: string;
  email: string;
  mfaEnabled: boolean;
}

export interface MFASetup {
  secret: string;
  qrCodeUrl: string;
  manualEntryKey: string;
}

export interface AuthResponse {
  success: boolean;
  message: string;
  requiresMFA?: boolean;
  sessionId?: string;
  mfaSetup?: MFASetup;
}
