import { Request, Response } from 'express';
import { authService } from '../services/auth';
import { redisService } from '../services/redis';
import { JWTUtils } from '../utils/crypto';
import {
   RegisterRequest,
   LoginRequest,
   MobileLoginRequest,
   RefreshTokenRequest,
   VerifyEmailRequest,
   ForgotPasswordRequest,
   ResetPasswordRequest,
   ChangePasswordRequest,
   RevokeTokenRequest
} from '../types';

/**
 * Authentication controller handling all auth-related endpoints
 */
export class AuthController {
   /**
    * Register a new user
    */
   async register(req: Request, res: Response): Promise<void> {
      try {
         const data: RegisterRequest = req.body;
         const result = await authService.register(data);

         res.status(201).json({
            message: 'User registered successfully. Please check your email for verification.',
            user: result.user,
         });
      } catch (error) {
         res.status(400).json({
            error: error instanceof Error ? error.message : 'Registration failed',
         });
      }
   }

   /**
    * Login user (browser or mobile)
    */
   async login(req: Request, res: Response): Promise<void> {
      try {
         const data: LoginRequest = req.body;
         const result = await authService.login(data);

         // Set refresh token as httpOnly cookie for browser clients
         if (data.clientType === 'browser' && result.refreshToken) {
            res.cookie('refreshToken', result.refreshToken, {
               httpOnly: true,
               secure: process.env['NODE_ENV'] === 'production',
               sameSite: process.env['NODE_ENV'] === 'production' ? 'strict' : 'lax',
               path: '/',
               maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            });

            // Remove refresh token from response body for browser clients
            delete result.refreshToken;
         }

         res.json({
            message: 'Login successful',
            ...result,
         });
      } catch (error) {
         res.status(401).json({
            error: error instanceof Error ? error.message : 'Login failed',
         });
      }
   }

   /**
    * Mobile login with PKCE
    */
   async mobileLogin(req: Request, res: Response): Promise<void> {
      try {
         const data: MobileLoginRequest = req.body;
         const result = await authService.mobileLogin(data);

         res.json({
            message: 'Mobile login successful',
            ...result,
         });
      } catch (error) {
         res.status(401).json({
            error: error instanceof Error ? error.message : 'Mobile login failed',
         });
      }
   }

   /**
    * Refresh access token
    */
   async refreshToken(req: Request, res: Response): Promise<void> {
      try {
         let refreshToken: string;

         // Check for refresh token in cookie (browser) or body (mobile)
         if (req.cookies['refreshToken']) {
            refreshToken = req.cookies['refreshToken'];
         } else {
            const data: RefreshTokenRequest = req.body;
            refreshToken = data.refreshToken;
         }

         if (!refreshToken) {
            res.status(401).json({ error: 'Refresh token required' });
            return;
         }

         const result = await authService.refreshToken({ refreshToken });

         // Update refresh token cookie for browser clients
         if (req.cookies['refreshToken'] && result.refreshToken) {
            res.cookie('refreshToken', result.refreshToken, {
               httpOnly: true,
               secure: process.env['NODE_ENV'] === 'production',
               sameSite: process.env['NODE_ENV'] === 'production' ? 'strict' : 'lax',
               path: '/',
               maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            });
         }

         res.json({
            message: 'Token refreshed successfully',
            accessToken: result.accessToken,
            refreshToken: result.refreshToken,
            user: result.user,
         });
      } catch (error) {
         res.status(401).json({
            error: error instanceof Error ? error.message : 'Token refresh failed',
         });
      }
   }

   /**
    * Logout user
    */
   async logout(req: Request, res: Response): Promise<void> {
      try {
         let refreshToken: string;

         // Check for refresh token in cookie (browser) or body (mobile)
         if (req.cookies['refreshToken']) {
            refreshToken = req.cookies['refreshToken'];
         } else {
            const data: RefreshTokenRequest = req.body;
            refreshToken = data.refreshToken;
         }

         if (refreshToken) {
            await authService.logout(refreshToken);
         }

         // Clear refresh token cookie
         res.clearCookie('refreshToken');

         res.json({ message: 'Logout successful' });
      } catch (error) {
         res.status(400).json({
            error: error instanceof Error ? error.message : 'Logout failed',
         });
      }
   }

   /**
    * Verify email with token
    */
   async verifyEmail(req: Request, res: Response): Promise<void> {
      try {
         const data: VerifyEmailRequest = req.body;
         await authService.verifyEmail(data);

         res.json({ message: 'Email verified successfully' });
      } catch (error) {
         res.status(400).json({
            error: error instanceof Error ? error.message : 'Email verification failed',
         });
      }
   }

   /**
    * Request password reset
    */
   async forgotPassword(req: Request, res: Response): Promise<void> {
      try {
         const data: ForgotPasswordRequest = req.body;
         await authService.forgotPassword(data);

         res.json({
            message: 'If the email exists, a password reset link has been sent'
         });
      } catch (error) {
         res.status(400).json({
            error: error instanceof Error ? error.message : 'Password reset request failed',
         });
      }
   }

   /**
    * Reset password with token
    */
   async resetPassword(req: Request, res: Response): Promise<void> {
      try {
         const data: ResetPasswordRequest = req.body;
         await authService.resetPassword(data);

         res.json({ message: 'Password reset successfully' });
      } catch (error) {
         res.status(400).json({
            error: error instanceof Error ? error.message : 'Password reset failed',
         });
      }
   }

   /**
    * Change password (authenticated user)
    */
   async changePassword(req: Request, res: Response): Promise<void> {
      try {
         const data: ChangePasswordRequest = req.body;
         const userId = (req as any).user.id;

         await authService.changePassword(userId, data);

         res.json({ message: 'Password changed successfully' });
      } catch (error) {
         res.status(400).json({
            error: error instanceof Error ? error.message : 'Password change failed',
         });
      }
   }

   /**
    * Get current user info
    */
   async getMe(req: Request, res: Response): Promise<void> {
      try {
         const userId = (req as any).user.id;
         const user = await authService.getUserById(userId);

         if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
         }

         res.json({ user });
      } catch (error) {
         res.status(500).json({
            error: error instanceof Error ? error.message : 'Failed to get user info',
         });
      }
   }

   /**
    * Revoke token by JTI (admin only)
    */
   async revokeToken(req: Request, res: Response): Promise<void> {
      try {
         const data: RevokeTokenRequest = req.body;
         const { jti } = data;

         // Decode token to get user ID
         const token = (req as any).token;
         const payload = JWTUtils.decodeToken(token);

         if (!payload) {
            res.status(400).json({ error: 'Invalid token' });
            return;
         }

         await redisService.revokeToken(jti, payload.sub, 'Admin revocation');

         res.json({ message: 'Token revoked successfully' });
      } catch (error) {
         res.status(400).json({
            error: error instanceof Error ? error.message : 'Token revocation failed',
         });
      }
   }

   /**
    * Emergency revoke all user tokens (admin only)
    */
   async emergencyRevoke(req: Request, res: Response): Promise<void> {
      try {
         const { userId } = req.body;

         if (!userId) {
            res.status(400).json({ error: 'User ID required' });
            return;
         }

         await redisService.revokeAllUserTokens(userId, 'Emergency revocation by admin');

         res.json({ message: 'All user tokens revoked successfully' });
      } catch (error) {
         res.status(400).json({
            error: error instanceof Error ? error.message : 'Emergency revocation failed',
         });
      }
   }
}

export const authController = new AuthController();
