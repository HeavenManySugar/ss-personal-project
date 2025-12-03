-- MFA Email Tokens Table
-- Run this to add email-based MFA support

-- MFA email verification tokens
CREATE TABLE IF NOT EXISTS mfa_email_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    verified INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_mfa_email_tokens_user_id ON mfa_email_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_email_tokens_code ON mfa_email_tokens(code);
CREATE INDEX IF NOT EXISTS idx_mfa_email_tokens_expires ON mfa_email_tokens(expires_at);
