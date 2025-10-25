import { PrismaClient, User, Role } from '@prisma/client';
import { PasswordUtils, TokenUtils } from '../utils/crypto';
import { redisService } from './redis';
import { rabbitmqService } from './rabbitmq';
import {
   RegisterRequest,
   LoginRequest,
   MobileLoginRequest,
   RefreshTokenRequest,
   AuthResponse,
   UserResponse,
   VerifyEmailRequest,
   ForgotPasswordRequest,
   ResetPasswordRequest,
   ChangePasswordRequest
} from '../types';

const prisma = new PrismaClient();

/**
 * Authentication service handling user registration, login, and token management
 */
export class AuthService {
   /**
    * Register a new user
    */
   async register(data: RegisterRequest): Promise<{ user: UserResponse; verificationToken: string }> {
      const { email, password } = data;

      // Check if user already exists
      const existingUser = await prisma.user.findUnique({
         where: { email: email.toLowerCase() },
      });

      if (existingUser) {
         throw new Error('User with this email already exists');
      }

      // Hash password
      const hashedPassword = await PasswordUtils.hashPassword(password);

      // Create user
      const user = await prisma.user.create({
         data: {
            email: email.toLowerCase(),
            password: hashedPassword,
            role: Role.USER,
            emailVerified: false,
         },
      });

      // Generate email verification token
      const verificationToken = TokenUtils.generateEmailVerificationToken();
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      await prisma.emailVerificationToken.create({
         data: {
            token: verificationToken,
            userId: user.id,
            expiresAt,
         },
      });

      // Log email verification (for development)
      console.log(`Email verification token for ${user.email}: ${verificationToken}`);
      console.log(`Verification link: http://localhost:3000/verify-email?token=${verificationToken}`);

      // Publish user created event to RabbitMQ
      try {
         await rabbitmqService.publishUserCreated(user.id);
      } catch (error) {
         console.error('Failed to publish user created event:', error);
         // Don't fail registration if RabbitMQ publishing fails
      }

      return {
         user: {
            id: user.id,
            email: user.email,
            role: user.role,
            emailVerified: user.emailVerified,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
         },
         verificationToken,
      };
   }

   /**
    * Login user (browser or mobile)
    */
   async login(data: LoginRequest): Promise<AuthResponse> {
      const { email, password, clientType = 'browser' } = data;

      // Find user
      const user = await prisma.user.findUnique({
         where: { email: email.toLowerCase() },
      });

      if (!user) {
         // Use constant time to prevent timing attacks
         await PasswordUtils.hashPassword('dummy');
         throw new Error('Invalid email or password');
      }

      // Verify password
      const isValidPassword = await PasswordUtils.verifyPassword(password, user.password);
      if (!isValidPassword) {
         throw new Error('Invalid email or password');
      }

      // Check if user is verified
      if (!user.emailVerified) {
         throw new Error('Email not verified. Please check your email for verification link.');
      }

      // Generate tokens
      const accessToken = this.generateAccessToken(user);
      const refreshToken = TokenUtils.generateRefreshToken();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      // Store refresh token
      await prisma.refreshToken.create({
         data: {
            token: refreshToken,
            userId: user.id,
            expiresAt,
         },
      });

      const response: AuthResponse = {
         accessToken,
         user: {
            id: user.id,
            email: user.email,
            role: user.role,
            emailVerified: user.emailVerified,
         },
      };

      // Include refresh token in response for mobile clients
      if (clientType === 'mobile') {
         response.refreshToken = refreshToken;
      }

      return response;
   }

   /**
    * Mobile login with PKCE
    */
   async mobileLogin(data: MobileLoginRequest): Promise<AuthResponse> {
      const { email, password, codeChallenge, codeChallengeMethod } = data;

      // Validate PKCE parameters
      if (codeChallengeMethod !== 'S256') {
         throw new Error('Unsupported code challenge method');
      }

      // Perform regular login first
      const loginResult = await this.login({ email, password, clientType: 'mobile' });

      // Store PKCE session for token exchange
      const sessionId = TokenUtils.generateToken();
      await redisService.storePKCESession(sessionId, {
         codeChallenge,
         userId: loginResult.user.id,
         expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
      });

      return loginResult;
   }

   /**
    * Refresh access token
    */
   async refreshToken(data: RefreshTokenRequest): Promise<AuthResponse> {
      const { refreshToken } = data;

      // Find refresh token
      const tokenRecord = await prisma.refreshToken.findUnique({
         where: { token: refreshToken },
         include: { user: true },
      });

      if (!tokenRecord || tokenRecord.isRevoked || tokenRecord.expiresAt < new Date()) {
         throw new Error('Invalid or expired refresh token');
      }

      // Check for token reuse (security feature)
      if (tokenRecord.replacedBy) {
         // Token has been replaced, revoke all tokens for this user
         await this.revokeAllUserTokens(tokenRecord.userId);
         throw new Error('Token has been reused. All sessions revoked for security.');
      }

      // Generate new tokens
      const newAccessToken = this.generateAccessToken(tokenRecord.user);
      const newRefreshToken = TokenUtils.generateRefreshToken();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      // Mark old token as replaced
      await prisma.refreshToken.update({
         where: { id: tokenRecord.id },
         data: { replacedBy: newRefreshToken },
      });

      // Create new refresh token
      await prisma.refreshToken.create({
         data: {
            token: newRefreshToken,
            userId: tokenRecord.userId,
            expiresAt,
         },
      });

      return {
         accessToken: newAccessToken,
         refreshToken: newRefreshToken,
         user: {
            id: tokenRecord.user.id,
            email: tokenRecord.user.email,
            role: tokenRecord.user.role,
            emailVerified: tokenRecord.user.emailVerified,
         },
      };
   }

   /**
    * Logout user (revoke refresh token)
    */
   async logout(refreshToken: string): Promise<void> {
      await prisma.refreshToken.updateMany({
         where: { token: refreshToken },
         data: { isRevoked: true },
      });
   }

   /**
    * Verify email with token
    */
   async verifyEmail(data: VerifyEmailRequest): Promise<void> {
      const { token } = data;

      const verificationRecord = await prisma.emailVerificationToken.findUnique({
         where: { token },
         include: { user: true },
      });

      if (!verificationRecord || verificationRecord.used || verificationRecord.expiresAt < new Date()) {
         throw new Error('Invalid or expired verification token');
      }

      // Mark email as verified
      await prisma.user.update({
         where: { id: verificationRecord.userId },
         data: { emailVerified: true },
      });

      // Mark token as used
      await prisma.emailVerificationToken.update({
         where: { id: verificationRecord.id },
         data: { used: true },
      });
   }

   /**
    * Request password reset
    */
   async forgotPassword(data: ForgotPasswordRequest): Promise<void> {
      const { email } = data;

      const user = await prisma.user.findUnique({
         where: { email: email.toLowerCase() },
      });

      if (!user) {
         // Don't reveal if user exists
         return;
      }

      // Generate reset token
      const resetToken = TokenUtils.generatePasswordResetToken();
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      await prisma.passwordResetToken.create({
         data: {
            token: resetToken,
            userId: user.id,
            expiresAt,
         },
      });

      // Log password reset (for development)
      console.log(`Password reset token for ${user.email}: ${resetToken}`);
      console.log(`Reset link: http://localhost:3000/reset-password?token=${resetToken}`);
   }

   /**
    * Reset password with token
    */
   async resetPassword(data: ResetPasswordRequest): Promise<void> {
      const { token, newPassword } = data;

      const resetRecord = await prisma.passwordResetToken.findUnique({
         where: { token },
         include: { user: true },
      });

      if (!resetRecord || resetRecord.used || resetRecord.expiresAt < new Date()) {
         throw new Error('Invalid or expired reset token');
      }

      // Hash new password
      const hashedPassword = await PasswordUtils.hashPassword(newPassword);

      // Update password
      await prisma.user.update({
         where: { id: resetRecord.userId },
         data: { password: hashedPassword },
      });

      // Mark token as used
      await prisma.passwordResetToken.update({
         where: { id: resetRecord.id },
         data: { used: true },
      });

      // Revoke all refresh tokens for security
      await this.revokeAllUserTokens(resetRecord.userId);
   }

   /**
    * Change password (authenticated user)
    */
   async changePassword(userId: string, data: ChangePasswordRequest): Promise<void> {
      const { currentPassword, newPassword } = data;

      const user = await prisma.user.findUnique({
         where: { id: userId },
      });

      if (!user) {
         throw new Error('User not found');
      }

      // Verify current password
      const isValidPassword = await PasswordUtils.verifyPassword(currentPassword, user.password);
      if (!isValidPassword) {
         throw new Error('Current password is incorrect');
      }

      // Hash new password
      const hashedPassword = await PasswordUtils.hashPassword(newPassword);

      // Update password
      await prisma.user.update({
         where: { id: userId },
         data: { password: hashedPassword },
      });

      // Revoke all refresh tokens for security
      await this.revokeAllUserTokens(userId);
   }

   /**
    * Get user by ID
    */
   async getUserById(userId: string): Promise<UserResponse | null> {
      const user = await prisma.user.findUnique({
         where: { id: userId },
      });

      if (!user) {
         return null;
      }

      return {
         id: user.id,
         email: user.email,
         role: user.role,
         emailVerified: user.emailVerified,
         createdAt: user.createdAt,
         updatedAt: user.updatedAt,
      };
   }

   /**
    * Generate access token for user
    */
   private generateAccessToken(user: User): string {
      const { JWTUtils } = require('../utils/crypto');
      return JWTUtils.generateAccessToken({
         sub: user.id,
         email: user.email,
         role: user.role,
      });
   }

   /**
    * Revoke all tokens for a user
    */
   private async revokeAllUserTokens(userId: string): Promise<void> {
      await prisma.refreshToken.updateMany({
         where: { userId },
         data: { isRevoked: true },
      });
   }
}

export const authService = new AuthService();
