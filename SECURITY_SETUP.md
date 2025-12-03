# Secure Login & User Authentication System

## Setup Instructions

### 1. Create D1 Database

```bash
# Create the D1 database
npx wrangler d1 create auth_system

# Copy the database_id from the output and update wrangler.json
```

Update `wrangler.json` with your `database_id`.

### 2. Initialize Database Schema

```bash
# Apply the schema
npx wrangler d1 execute auth_system --file=./schema.sql
```

### 3. Install Dependencies

```bash
npm install
```

### 4. Run Development Server

```bash
npm run dev
```

### 5. Deploy to Cloudflare

```bash
# Deploy to production
npm run deploy
```

## Security Features Implemented

### 1. Password Security
- **PBKDF2 Hashing**: Uses Web Crypto API with 100,000 iterations
- **Salt**: Unique 16-byte salt for each user
- **No Plain Text Storage**: Passwords never stored in plain text

### 2. Multi-Factor Authentication (MFA)
- **TOTP-based**: Time-based One-Time Password (RFC 6238)
- **QR Code Generation**: Easy setup with Google Authenticator
- **Backup Codes**: Optional recovery mechanism

### 3. SQL Injection Prevention
- **Prepared Statements**: All queries use parameterized statements
- **Input Validation**: Server-side validation for all inputs
- **Type Safety**: TypeScript for compile-time checks

### 4. XSS Prevention
- **Output Escaping**: Automatic escaping in Astro templates
- **Content Security Policy**: Restricts inline scripts
- **Input Sanitization**: HTML tags stripped from user input

### 5. Session Security
- **Secure Cookies**: HttpOnly, Secure, SameSite flags
- **CSRF Protection**: Token-based CSRF prevention
- **Session Expiration**: Automatic timeout after 24 hours
- **Session Invalidation**: Proper logout handling

### 6. Additional Security Measures
- **Rate Limiting**: Login attempt throttling
- **Account Locking**: Temporary lock after 5 failed attempts
- **Audit Logging**: All authentication events logged
- **IP Tracking**: Session binding to IP address

## Testing

### XSS Testing
Try injecting: `<script>alert('XSS')</script>` in any input field.
**Expected**: Input sanitized, no script execution.

### SQL Injection Testing
Try username: `admin' OR '1'='1`
**Expected**: Login fails, no database compromise.

### MFA Testing
1. Register a new account
2. Enable MFA from dashboard
3. Scan QR code with Google Authenticator
4. Logout and login again
5. Enter 6-digit code from authenticator

## Architecture

```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │ HTTPS
       ▼
┌─────────────────┐
│  Astro Pages    │ ← UI Components (SSR)
│  - Register     │
│  - Login        │
│  - Dashboard    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  API Endpoints  │ ← Authentication Logic
│  /api/auth/*    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Security Layer │ ← Hashing, MFA, Validation
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Cloudflare D1  │ ← SQLite Database
│  - users        │
│  - sessions     │
│  - login_logs   │
└─────────────────┘
```

## Project Structure

```
src/
├── pages/
│   ├── register.astro       # Registration page
│   ├── login.astro          # Login page
│   ├── verify-mfa.astro     # MFA verification page
│   ├── dashboard.astro      # User dashboard
│   └── api/
│       └── auth/
│           ├── register.ts   # Registration API
│           ├── login.ts      # Login API
│           ├── verify-mfa.ts # MFA verification API
│           ├── logout.ts     # Logout API
│           └── setup-mfa.ts  # MFA setup API
├── lib/
│   ├── crypto.ts            # Password hashing utilities
│   ├── mfa.ts               # TOTP generation/verification
│   ├── session.ts           # Session management
│   ├── validation.ts        # Input validation
│   └── security.ts          # Security utilities
└── types/
    └── auth.ts              # TypeScript types
```

## Report Contents (3-5 pages)

1. **Introduction**: Project overview and objectives
2. **System Design**: Architecture diagram and security mechanisms
3. **Implementation**: Code explanation with examples
4. **Testing & Results**: XSS, SQL Injection, MFA tests with screenshots
5. **Conclusion**: Summary and lessons learned

## Credits

- **Student Name**: [Your Name]
- **Student ID**: [Your ID]
- **Course**: System Security
- **Due Date**: 2025/12/03
