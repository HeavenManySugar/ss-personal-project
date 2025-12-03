/**
 * Email Service using Resend
 * Sends verification emails via Resend API
 */

export interface EmailConfig {
  apiKey: string;
  fromEmail: string;
  fromName: string;
}

export interface VerificationEmail {
  to: string;
  username: string;
  code: string;
  token: string;
  siteUrl: string;
}

/**
 * Generate verification email HTML
 */
function generateVerificationEmailHTML(data: VerificationEmail): string {
  const verifyUrl = `${data.siteUrl}/verify-email?token=${data.token}`;
  
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify Your Email</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #4CAF50; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
    .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
    .code-box { background: white; border: 2px dashed #4CAF50; padding: 20px; text-align: center; margin: 20px 0; border-radius: 4px; }
    .code { font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #4CAF50; }
    .button { display: inline-block; background: #4CAF50; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; margin: 20px 0; }
    .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔐 Verify Your Email</h1>
    </div>
    <div class="content">
      <p>Hi <strong>${data.username}</strong>,</p>
      <p>Thank you for registering! Please verify your email address to complete your registration.</p>
      
      <div class="code-box">
        <p>Your verification code is:</p>
        <div class="code">${data.code}</div>
      </div>
      
      <p>Or click the button below to verify automatically:</p>
      <center>
        <a href="${verifyUrl}" class="button">Verify Email Address</a>
      </center>
      
      <p>This code will expire in 15 minutes.</p>
      <p>If you didn't create an account, please ignore this email.</p>
    </div>
    <div class="footer">
      <p>This is an automated email. Please do not reply.</p>
    </div>
  </div>
</body>
</html>
  `.trim();
}

/**
 * Generate verification email plain text
 */
function generateVerificationEmailText(data: VerificationEmail): string {
  const verifyUrl = `${data.siteUrl}/verify-email?token=${data.token}`;
  
  return `
Verify Your Email

Hi ${data.username},

Thank you for registering! Please verify your email address to complete your registration.

Your verification code is: ${data.code}

Or visit this link to verify automatically:
${verifyUrl}

This code will expire in 15 minutes.

If you didn't create an account, please ignore this email.

---
This is an automated email. Please do not reply.
  `.trim();
}

/**
 * Send verification email using Resend API
 */
export async function sendVerificationEmail(
  config: EmailConfig,
  data: VerificationEmail
): Promise<boolean> {
  try {
    const htmlBody = generateVerificationEmailHTML(data);
    const textBody = generateVerificationEmailText(data);

    // Send via Resend API
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.apiKey}`
      },
      body: JSON.stringify({
        from: `${config.fromName} <${config.fromEmail}>`,
        to: [data.to],
        subject: 'Verify Your Email Address',
        text: textBody,
        html: htmlBody
      })
    });

    if (!response.ok) {
      const error = await response.text();
      console.error('Resend API error:', error);
      return false;
    }

    return true;
  } catch (error) {
    console.error('Failed to send verification email:', error);
    return false;
  }
}

/**
 * Generate random 6-digit verification code
 */
export function generateVerificationCode(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

/**
 * Generate secure verification token
 */
export async function generateVerificationToken(): Promise<string> {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}
