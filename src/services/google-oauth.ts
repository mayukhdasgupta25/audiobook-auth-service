import { OAuth2Client } from 'google-auth-library';
import { config } from '../config/env';

/**
 * Google OAuth service for token verification
 */
export class GoogleOAuthService {
   private client: OAuth2Client;

   constructor() {
      if (!config.GOOGLE_CLIENT_ID) {
         throw new Error('GOOGLE_CLIENT_ID is required for Google OAuth');
      }
      this.client = new OAuth2Client(config.GOOGLE_CLIENT_ID);
   }

   /**
    * Verify Google ID token and extract user information
    * @param token - Google ID token from client
    * @returns User information from verified token
    * @throws Error if token is invalid
    */
   async verifyGoogleToken(token: string): Promise<{
      email: string;
      googleId: string;
      emailVerified: boolean;
      name?: string;
      picture?: string;
   }> {
      try {
         // Verify the token with Google
         const ticket = await this.client.verifyIdToken({
            idToken: token,
            audience: config.GOOGLE_CLIENT_ID,
         });

         const payload = ticket.getPayload();

         if (!payload) {
            throw new Error('Invalid Google token: no payload');
         }

         // Extract required information
         const email = payload.email;
         const googleId = payload.sub; // Google's unique user ID
         const emailVerified = payload.email_verified === true;

         if (!email) {
            throw new Error('Invalid Google token: email not provided');
         }

         if (!googleId) {
            throw new Error('Invalid Google token: Google ID not provided');
         }

         const result: {
            email: string;
            googleId: string;
            emailVerified: boolean;
            name?: string;
            picture?: string;
         } = {
            email: email.toLowerCase(),
            googleId,
            emailVerified,
         };

         // Only include optional fields if they exist
         if (payload.name) {
            result.name = payload.name;
         }
         if (payload.picture) {
            result.picture = payload.picture;
         }

         return result;
      } catch (error) {
         if (error instanceof Error) {
            throw new Error(`Google token verification failed: ${error.message}`);
         }
         throw new Error('Google token verification failed: unknown error');
      }
   }
}

export const googleOAuthService = new GoogleOAuthService();

