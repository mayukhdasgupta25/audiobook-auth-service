import { User, Role } from '@prisma/client';

// JWT Payload interface
export interface JWTPayload {
   sub: string; // User ID
   email: string;
   role: Role;
   iat: number;
   exp: number;
   jti: string; // JWT ID for revocation
   iss: string; // Issuer
}

// JWT Header interface
export interface JWTHeader {
   alg: 'RS256';
   typ: 'JWT';
   kid: string; // Key ID
}

// JWKS Key interface
export interface JWK {
   kid: string;
   kty: 'RSA';
   use: 'sig';
   alg: 'RS256';
   n: string; // Modulus
   e: string; // Exponent
}

export interface JWKS {
   keys: JWK[];
}

// Request/Response interfaces
export interface RegisterRequest {
   email: string;
   password: string;
}

export interface LoginRequest {
   email: string;
   password: string;
   clientType?: 'browser' | 'mobile';
   app?: string;
}

export interface MobileLoginRequest extends LoginRequest {
   codeChallenge: string;
   codeChallengeMethod: 'S256';
}

export interface RefreshTokenRequest {
   refreshToken: string;
}

export interface VerifyEmailRequest {
   token: string;
}

export interface ForgotPasswordRequest {
   email: string;
}

export interface ResetPasswordRequest {
   token: string;
   newPassword: string;
}

export interface ChangePasswordRequest {
   currentPassword: string;
   newPassword: string;
}

export interface RevokeTokenRequest {
   jti: string;
}

export interface GoogleOAuthRequest {
   token: string;
   clientType?: 'browser' | 'mobile';
   app?: string;
}

// Response interfaces
export interface AuthResponse {
   accessToken: string;
   refreshToken?: string; // Only for mobile clients
   user: {
      id: string;
      email: string;
      role: Role;
      emailVerified: boolean;
   };
}

export interface UserResponse {
   id: string;
   email: string;
   role: Role;
   emailVerified: boolean;
   createdAt: Date;
   updatedAt: Date;
}

// Error classes
export class AuthError extends Error {
   statusCode: number;
   code: string;

   constructor(message: string, statusCode: number = 401, code: string = 'AUTH_ERROR') {
      super(message);
      this.statusCode = statusCode;
      this.code = code;
      this.name = 'AuthError';
   }
}

export class ValidationError extends Error {
   statusCode: number;
   code: string;
   details: Record<string, string[]>;

   constructor(message: string, details: Record<string, string[]> = {}, statusCode: number = 400, code: string = 'VALIDATION_ERROR') {
      super(message);
      this.statusCode = statusCode;
      this.code = code;
      this.details = details;
      this.name = 'ValidationError';
   }
}

// Middleware interfaces
export interface AuthenticatedRequest {
   user?: User;
   token?: string;
}

// PKCE interfaces
export interface PKCESession {
   codeChallenge: string;
   codeChallengeMethod: string;
   userId?: string;
   expiresAt: Date;
}

// Token rotation interfaces
export interface TokenFamily {
   userId: string;
   tokens: string[];
   createdAt: Date;
}

// Redis interfaces
export interface RevokedToken {
   jti: string;
   userId: string;
   revokedAt: Date;
   reason?: string;
}

// Email interfaces
export interface EmailTemplate {
   to: string;
   subject: string;
   html: string;
   text: string;
}

export interface EmailVerificationData {
   email: string;
   token: string;
   expiresAt: Date;
}

export interface PasswordResetData {
   email: string;
   token: string;
   expiresAt: Date;
}
