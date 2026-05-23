import { PrismaClient, EmailType } from '@prisma/client';
import { config } from '../config/env';

// Prisma 7 reads connection from prisma.config.ts automatically
const prisma = new PrismaClient();

/**
 * Email service for sending emails via HTTP API
 */
export class EmailService {
   /**
    * Send OTP email to user
    * @param email - Recipient email address
    * @param otp - OTP code to send
    * @param purpose - Purpose of OTP (for email content)
    * @param userId - Optional user ID for logging
    */
   async sendOTPEmail(email: string, otp: string, purpose: string, userId?: string): Promise<void> {
      const subject = `Your OTP Code - ${purpose}`;
      const body = this.generateOTPEmailBody(otp, purpose);

      try {
         // Send email via HTTP API if EMAIL_SERVICE_URL is configured
         if (config.EMAIL_SERVICE_URL) {
            await this.sendEmailViaAPI(email, subject, body);
         } else {
            // Log email in development (for testing)
            console.log(`[EMAIL] To: ${email}`);
            console.log(`[EMAIL] Subject: ${subject}`);
            console.log(`[EMAIL] Body: ${body}`);
            console.log(`[EMAIL] OTP Code: ${otp}`);
         }

         // Log email to database
         await this.logEmail(email, subject, body, EmailType.OTP, userId);
      } catch (error) {
         // Log error but don't fail the auth flow
         console.error('Failed to send OTP email:', error);
         // Still log the email attempt to database
         try {
            await this.logEmail(email, subject, body, EmailType.OTP, userId);
         } catch (logError) {
            console.error('Failed to log email:', logError);
         }
      }
   }

   /**
    * Generate OTP email body
    */
   private generateOTPEmailBody(otp: string, purpose: string): string {
      return `
Your OTP code for ${purpose} is: ${otp}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.

Best regards,
AudioBook Team
      `.trim();
   }

   /**
    * Send email via HTTP API
    */
   private async sendEmailViaAPI(email: string, subject: string, body: string): Promise<void> {
      if (!config.EMAIL_SERVICE_URL) {
         throw new Error('EMAIL_SERVICE_URL not configured');
      }

      const response = await fetch(config.EMAIL_SERVICE_URL, {
         method: 'POST',
         headers: {
            'Content-Type': 'application/json',
         },
         body: JSON.stringify({
            to: email,
            from: config.EMAIL_FROM,
            subject: subject,
            text: body,
            html: this.generateHTMLBody(body),
         }),
      });

      if (!response.ok) {
         throw new Error(`Email service returned status ${response.status}`);
      }
   }

   /**
    * Generate HTML body from text
    */
   private generateHTMLBody(text: string): string {
      // Convert plain text to HTML, preserving line breaks
      const html = text
         .split('\n')
         .map((line) => {
            if (line.trim() === '') {
               return '<br>';
            }
            // Highlight OTP code if it's a 6-digit number
            const otpMatch = line.match(/(\d{6})/);
            if (otpMatch) {
               return line.replace(
                  otpMatch[0],
                  `<strong style="font-size: 24px; color: #007bff;">${otpMatch[0]}</strong>`
               );
            }
            return line;
         })
         .join('<br>');

      return `
<!DOCTYPE html>
<html>
<head>
   <meta charset="utf-8">
   <style>
      body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
   </style>
</head>
<body>
   ${html}
</body>
</html>
      `.trim();
   }

   /**
    * Log email to database
    */
   private async logEmail(
      recipientAddress: string,
      subject: string,
      body: string,
      emailType: EmailType,
      userId?: string
   ): Promise<void> {
      try {
         await prisma.emailLog.create({
            data: {
               subject,
               body,
               recipientAddress,
               senderAddress: config.EMAIL_FROM,
               emailType,
               userId: userId || null,
               sentAt: new Date(),
            },
         });
      } catch (error) {
         // Log error but don't throw - email logging shouldn't break the flow
         console.error('Failed to log email to database:', error);
      }
   }
}

export const emailService = new EmailService();

