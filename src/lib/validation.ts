/**
 * Input validation utilities to prevent XSS and SQL Injection
 */

/**
 * Sanitize user input by removing HTML tags and dangerous characters
 * Prevents XSS attacks
 */
export function sanitizeInput(input: string): string {
  if (!input) return '';
  
  // Remove HTML tags
  let sanitized = input.replace(/<[^>]*>/g, '');
  
  // Remove dangerous characters
  sanitized = sanitized.replace(/[<>'"&]/g, (char) => {
    const entities: Record<string, string> = {
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '&': '&amp;'
    };
    return entities[char] || char;
  });
  
  return sanitized.trim();
}

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email) && email.length <= 255;
}

/**
 * Validate username format
 * - 3-50 characters
 * - Alphanumeric, underscore, hyphen only
 */
export function isValidUsername(username: string): boolean {
  const usernameRegex = /^[a-zA-Z0-9_-]{3,50}$/;
  return usernameRegex.test(username);
}

/**
 * Validate password strength
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character
 */
export function isValidPassword(password: string): { valid: boolean; message: string } {
  if (password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters long' };
  }
  
  if (!/[A-Z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter' };
  }
  
  if (!/[a-z]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter' };
  }
  
  if (!/[0-9]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one number' };
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one special character' };
  }
  
  return { valid: true, message: 'Password is strong' };
}

/**
 * Validate TOTP code format
 */
export function isValidTOTPCode(code: string): boolean {
  return /^\d{6}$/.test(code);
}

/**
 * Escape SQL LIKE wildcards
 * Prevents SQL injection in LIKE queries
 */
export function escapeSQLLike(input: string): string {
  return input.replace(/[%_]/g, '\\$&');
}

/**
 * Validate and sanitize registration data
 */
export function validateRegistration(data: {
  username?: string;
  email?: string;
  password?: string;
}): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!data.username) {
    errors.push('Username is required');
  } else if (!isValidUsername(data.username)) {
    errors.push('Username must be 3-50 characters and contain only letters, numbers, underscore, or hyphen');
  }
  
  if (!data.email) {
    errors.push('Email is required');
  } else if (!isValidEmail(data.email)) {
    errors.push('Invalid email format');
  }
  
  if (!data.password) {
    errors.push('Password is required');
  } else {
    const passwordCheck = isValidPassword(data.password);
    if (!passwordCheck.valid) {
      errors.push(passwordCheck.message);
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Validate and sanitize login data
 */
export function validateLogin(data: {
  username?: string;
  password?: string;
}): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!data.username) {
    errors.push('Username is required');
  }
  
  if (!data.password) {
    errors.push('Password is required');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Check if an account is locked
 */
export function isAccountLocked(lockedUntil: string | null): boolean {
  if (!lockedUntil) return false;
  return new Date(lockedUntil) > new Date();
}

/**
 * Calculate account lock time
 * @param failedAttempts - Number of failed login attempts
 * @returns ISO timestamp for when account should be unlocked, or null
 */
export function calculateLockTime(failedAttempts: number): string | null {
  const MAX_ATTEMPTS = 5;
  const LOCK_DURATION = 15 * 60 * 1000; // 15 minutes
  
  if (failedAttempts >= MAX_ATTEMPTS) {
    const lockUntil = new Date(Date.now() + LOCK_DURATION);
    return lockUntil.toISOString();
  }
  
  return null;
}
