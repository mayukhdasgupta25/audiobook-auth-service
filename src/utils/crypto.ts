import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import forge from 'node-forge';
import { config } from '../config/env';
import { JWTPayload, JWTHeader, JWK, JWKS } from '../types';

/**
 * Password hashing utilities using Argon2id
 */
export class PasswordUtils {
   /**
    * Hash a password using Argon2id
    */
   static async hashPassword(password: string): Promise<string> {
      try {
         return await argon2.hash(password, {
            type: argon2.argon2id,
            memoryCost: config.ARGON2_MEMORY,
            timeCost: config.ARGON2_ITERATIONS,
            parallelism: config.ARGON2_PARALLELISM,
         });
      } catch (_error) {
         throw new Error('Failed to hash password');
      }
   }

   /**
    * Verify a password against its hash
    */
   static async verifyPassword(password: string, hash: string): Promise<boolean> {
      try {
         return await argon2.verify(hash, password);
      } catch (_error) {
         return false;
      }
   }
}

/**
 * JWT utilities for token generation and verification
 */
export class JWTUtils {
   /**
    * Generate a JWT access token
    */
   static generateAccessToken(payload: Omit<JWTPayload, 'iat' | 'exp' | 'jti' | 'iss'>): string {
      const now = Math.floor(Date.now() / 1000);
      const jti = crypto.randomUUID();

      const fullPayload: JWTPayload = {
         ...payload,
         iat: now,
         exp: now + this.parseExpiry(config.JWT_ACCESS_TOKEN_EXPIRY),
         jti,
         iss: config.JWT_ISSUER,
      };

      const header: JWTHeader = {
         alg: 'RS256',
         typ: 'JWT',
         kid: config.JWT_KEY_ID,
      };

      return jwt.sign(fullPayload, config.JWT_PRIVATE_KEY, {
         algorithm: 'RS256',
         header: header,
      });
   }

   /**
    * Verify a JWT access token
    */
   static verifyAccessToken(token: string): JWTPayload {
      try {
         return jwt.verify(token, config.JWT_PUBLIC_KEY, {
            algorithms: ['RS256'],
            issuer: config.JWT_ISSUER,
         }) as JWTPayload;
      } catch (_error) {
         throw new Error('Invalid or expired token');
      }
   }

   /**
    * Decode JWT without verification (for debugging)
    */
   static decodeToken(token: string): JWTPayload | null {
      try {
         return jwt.decode(token) as JWTPayload;
      } catch (_error) {
         return null;
      }
   }

   /**
    * Parse expiry string to seconds
    */
   private static parseExpiry(expiry: string): number {
      const match = expiry.match(/^(\d+)([smhd])$/);
      if (!match) {
         throw new Error('Invalid expiry format');
      }

      const value = parseInt(match[1]!, 10);
      const unit = match[2]!;

      switch (unit) {
         case 's': return value;
         case 'm': return value * 60;
         case 'h': return value * 60 * 60;
         case 'd': return value * 24 * 60 * 60;
         default: throw new Error('Invalid expiry unit');
      }
   }
}

/**
 * Cryptographic utilities
 */
export class CryptoUtils {
   /**
    * Generate a cryptographically secure random token
    */
   static generateSecureToken(length: number = 32): string {
      return crypto.randomBytes(length).toString('hex');
   }

   /**
    * Generate PKCE code verifier
    */
   static generateCodeVerifier(): string {
      return crypto.randomBytes(32).toString('base64url');
   }

   /**
    * Generate PKCE code challenge from verifier
    */
   static generateCodeChallenge(codeVerifier: string): string {
      return crypto
         .createHash('sha256')
         .update(codeVerifier)
         .digest('base64url');
   }

   /**
    * Verify PKCE code challenge
    */
   static verifyCodeChallenge(codeVerifier: string, codeChallenge: string): boolean {
      const expectedChallenge = this.generateCodeChallenge(codeVerifier);
      return expectedChallenge === codeChallenge;
   }

   /**
    * Generate RSA key pair
    */
   static generateRSAKeyPair(): { privateKey: string; publicKey: string } {
      const keypair = forge.pki.rsa.generateKeyPair(2048);
      const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
      const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);

      return {
         privateKey: privateKeyPem,
         publicKey: publicKeyPem,
      };
   }

   /**
    * Convert PEM public key to JWK format
    */
   static pemToJWK(publicKeyPem: string, kid: string): JWK {
      const publicKey = crypto.createPublicKey(publicKeyPem);
      const jwk = publicKey.export({ format: 'jwk' });

      return {
         kid,
         kty: 'RSA',
         use: 'sig',
         alg: 'RS256',
         n: jwk.n || '',
         e: jwk.e || '',
      };
   }

   /**
    * Generate JWKS (JSON Web Key Set)
    */
   static generateJWKS(publicKeyPem: string, kid: string): JWKS {
      const jwk = this.pemToJWK(publicKeyPem, kid);
      return {
         keys: [jwk],
      };
   }
}

/**
 * Token utilities for refresh tokens and verification tokens
 */
export class TokenUtils {
   /**
    * Generate a secure random token for refresh/verification
    */
   static generateToken(): string {
      return crypto.randomBytes(32).toString('hex');
   }

   /**
    * Generate email verification token
    */
   static generateEmailVerificationToken(): string {
      return this.generateToken();
   }

   /**
    * Generate password reset token
    */
   static generatePasswordResetToken(): string {
      return this.generateToken();
   }

   /**
    * Generate refresh token
    */
   static generateRefreshToken(): string {
      return this.generateToken();
   }
}
