-- Cleanup Script for Unverified Accounts and Expired Tokens
-- Run this periodically (e.g., daily via cron job)

-- Delete unverified accounts older than 7 days
DELETE FROM users 
WHERE email_verified = 0 
AND created_at < datetime('now', '-7 days');

-- Delete expired email verification tokens (older than 1 day)
DELETE FROM email_verification_tokens 
WHERE expires_at < datetime('now', '-1 day');

-- Delete expired MFA email tokens (older than 1 day)
DELETE FROM mfa_email_tokens 
WHERE expires_at < datetime('now', '-1 day');

-- Vacuum to reclaim space
VACUUM;
