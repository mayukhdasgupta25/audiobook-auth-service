import {
   PasswordUtils,
   JWTUtils,
   CryptoUtils,
   TokenUtils,
} from '../../src/utils/crypto';
import { Role } from '@prisma/client';

describe('PasswordUtils', () => {
   describe('hashPassword', () => {
      test('should hash password successfully', async () => {
         const password = 'testPassword123';
         const hash = await PasswordUtils.hashPassword(password);

         expect(hash).toBeDefined();
         expect(hash).not.toBe(password);
         expect(typeof hash).toBe('string');
         expect(hash.length).toBeGreaterThan(0);
      });

      test('should produce unique hashes for same password', async () => {
         const password = 'testPassword123';
         const hash1 = await PasswordUtils.hashPassword(password);
         const hash2 = await PasswordUtils.hashPassword(password);

         expect(hash1).not.toBe(hash2);
      });

      test('should handle various password lengths', async () => {
         const shortPassword = '12345';
         const longPassword = 'a'.repeat(100);
         const specialPassword = '!@#$%^&*()';

         const hash1 = await PasswordUtils.hashPassword(shortPassword);
         const hash2 = await PasswordUtils.hashPassword(longPassword);
         const hash3 = await PasswordUtils.hashPassword(specialPassword);

         expect(hash1).toBeDefined();
         expect(hash2).toBeDefined();
         expect(hash3).toBeDefined();
      });
   });

   describe('verifyPassword', () => {
      test('should verify correct password', async () => {
         const password = 'testPassword123';
         const hash = await PasswordUtils.hashPassword(password);

         const isValid = await PasswordUtils.verifyPassword(password, hash);
         expect(isValid).toBe(true);
      });

      test('should reject incorrect password', async () => {
         const password = 'testPassword123';
         const hash = await PasswordUtils.hashPassword(password);

         const isValid = await PasswordUtils.verifyPassword('wrongPassword', hash);
         expect(isValid).toBe(false);
      });

      test('should reject empty password', async () => {
         const password = 'testPassword123';
         const hash = await PasswordUtils.hashPassword(password);

         const isValid = await PasswordUtils.verifyPassword('', hash);
         expect(isValid).toBe(false);
      });

      test('should handle invalid hash format gracefully', async () => {
         const password = 'testPassword123';
         const invalidHash = 'invalid_hash_format';

         const isValid = await PasswordUtils.verifyPassword(password, invalidHash);
         expect(isValid).toBe(false);
      });
   });
});

describe('JWTUtils', () => {
   describe('generateAccessToken', () => {
      test('should generate access token with correct payload structure', () => {
         const payload = {
            sub: 'user123',
            email: 'test@example.com',
            role: 'USER' as Role,
         };

         const token = JWTUtils.generateAccessToken(payload);
         expect(token).toBeDefined();
         expect(typeof token).toBe('string');
         expect(token.split('.').length).toBe(3);
      });

      test('should include all required fields in token', () => {
         const payload = {
            sub: 'user123',
            email: 'test@example.com',
            role: 'USER' as Role,
         };

         const token = JWTUtils.generateAccessToken(payload);
         const decoded = JWTUtils.decodeToken(token);

         expect(decoded).not.toBeNull();
         expect(decoded?.sub).toBe(payload.sub);
         expect(decoded?.email).toBe(payload.email);
         expect(decoded?.role).toBe(payload.role);
         expect(decoded?.iat).toBeDefined();
         expect(decoded?.exp).toBeDefined();
         expect(decoded?.jti).toBeDefined();
         expect(decoded?.iss).toBeDefined();
      });

      test('should generate unique tokens for same payload', () => {
         const payload = {
            sub: 'user123',
            email: 'test@example.com',
            role: 'USER' as Role,
         };

         const token1 = JWTUtils.generateAccessToken(payload);
         const token2 = JWTUtils.generateAccessToken(payload);

         expect(token1).not.toBe(token2);
      });

      test('should have different timestamps for repeated calls', () => {
         const payload = {
            sub: 'user123',
            email: 'test@example.com',
            role: 'USER' as Role,
         };

         const token1 = JWTUtils.generateAccessToken(payload);
         const decoded1 = JWTUtils.decodeToken(token1);

         setTimeout(() => {
            const token2 = JWTUtils.generateAccessToken(payload);
            const decoded2 = JWTUtils.decodeToken(token2);

            if (decoded1 && decoded2) {
               expect(decoded1.iat).toBeLessThanOrEqual(decoded2.iat);
            }
         }, 10);
      });
   });

   describe('decodeToken', () => {
      test('should decode valid token without verification', () => {
         const payload = {
            sub: 'user123',
            email: 'test@example.com',
            role: 'USER' as Role,
         };

         const token = JWTUtils.generateAccessToken(payload);
         const decoded = JWTUtils.decodeToken(token);

         expect(decoded).not.toBeNull();
         expect(decoded?.sub).toBe(payload.sub);
         expect(decoded?.email).toBe(payload.email);
         expect(decoded?.role).toBe(payload.role);
      });

      test('should return null for invalid token', () => {
         const invalidToken = 'invalid.jwt.token';
         const decoded = JWTUtils.decodeToken(invalidToken);

         expect(decoded).toBeNull();
      });

      test('should return null for malformed token', () => {
         const malformedToken = 'not.a.valid.token.structure';
         const decoded = JWTUtils.decodeToken(malformedToken);

         expect(decoded).toBeNull();
      });

      test('should return null for empty token', () => {
         const decoded = JWTUtils.decodeToken('');

         expect(decoded).toBeNull();
      });
   });
});

describe('CryptoUtils', () => {
   describe('generateSecureToken', () => {
      test('should generate secure token with default length', () => {
         const token = CryptoUtils.generateSecureToken();

         expect(token).toBeDefined();
         expect(typeof token).toBe('string');
         expect(token.length).toBe(64); // 32 bytes = 64 hex chars
      });

      test('should generate tokens with specified length', () => {
         const token16 = CryptoUtils.generateSecureToken(16);
         const token64 = CryptoUtils.generateSecureToken(64);

         expect(token16.length).toBe(32); // 16 bytes = 32 hex chars
         expect(token64.length).toBe(128); // 64 bytes = 128 hex chars
      });

      test('should generate unique tokens', () => {
         const token1 = CryptoUtils.generateSecureToken();
         const token2 = CryptoUtils.generateSecureToken();

         expect(token1).not.toBe(token2);
      });

      test('should generate tokens with only hex characters', () => {
         const token = CryptoUtils.generateSecureToken();
         expect(token).toMatch(/^[0-9a-f]{64}$/);
      });
   });

   describe('generateCodeVerifier', () => {
      test('should generate code verifier in base64url format', () => {
         const codeVerifier = CryptoUtils.generateCodeVerifier();

         expect(codeVerifier).toBeDefined();
         expect(typeof codeVerifier).toBe('string');
         expect(codeVerifier.length).toBeGreaterThan(0);
      });

      test('should generate unique verifiers', () => {
         const verifier1 = CryptoUtils.generateCodeVerifier();
         const verifier2 = CryptoUtils.generateCodeVerifier();

         expect(verifier1).not.toBe(verifier2);
      });

      test('should generate verifier with safe URL characters', () => {
         const codeVerifier = CryptoUtils.generateCodeVerifier();

         expect(codeVerifier).not.toContain('+');
         expect(codeVerifier).not.toContain('/');
         expect(codeVerifier).not.toContain('=');
         expect(codeVerifier).not.toContain(' ');
      });
   });

   describe('generateCodeChallenge', () => {
      test('should generate code challenge from verifier', () => {
         const codeVerifier = CryptoUtils.generateCodeVerifier();
         const codeChallenge = CryptoUtils.generateCodeChallenge(codeVerifier);

         expect(codeChallenge).toBeDefined();
         expect(typeof codeChallenge).toBe('string');
         expect(codeChallenge.length).toBeGreaterThan(0);
      });

      test('should generate same challenge for same verifier', () => {
         const codeVerifier = CryptoUtils.generateCodeVerifier();
         const challenge1 = CryptoUtils.generateCodeChallenge(codeVerifier);
         const challenge2 = CryptoUtils.generateCodeChallenge(codeVerifier);

         expect(challenge1).toBe(challenge2);
      });

      test('should generate different challenges for different verifiers', () => {
         const verifier1 = CryptoUtils.generateCodeVerifier();
         const verifier2 = CryptoUtils.generateCodeVerifier();

         const challenge1 = CryptoUtils.generateCodeChallenge(verifier1);
         const challenge2 = CryptoUtils.generateCodeChallenge(verifier2);

         expect(challenge1).not.toBe(challenge2);
      });

      test('should not contain padding or unsafe URL characters', () => {
         const codeVerifier = CryptoUtils.generateCodeVerifier();
         const codeChallenge = CryptoUtils.generateCodeChallenge(codeVerifier);

         expect(codeChallenge).not.toContain('+');
         expect(codeChallenge).not.toContain('/');
         expect(codeChallenge).not.toContain('=');
      });
   });

   describe('verifyCodeChallenge', () => {
      test('should verify correct code challenge', () => {
         const codeVerifier = CryptoUtils.generateCodeVerifier();
         const codeChallenge = CryptoUtils.generateCodeChallenge(codeVerifier);

         const isValid = CryptoUtils.verifyCodeChallenge(codeVerifier, codeChallenge);
         expect(isValid).toBe(true);
      });

      test('should reject incorrect code challenge', () => {
         const codeVerifier = CryptoUtils.generateCodeVerifier();
         const wrongChallenge = 'wrong_challenge_string';

         const isValid = CryptoUtils.verifyCodeChallenge(codeVerifier, wrongChallenge);
         expect(isValid).toBe(false);
      });

      test('should reject challenge from different verifier', () => {
         const verifier1 = CryptoUtils.generateCodeVerifier();
         const verifier2 = CryptoUtils.generateCodeVerifier();
         const challenge2 = CryptoUtils.generateCodeChallenge(verifier2);

         const isValid = CryptoUtils.verifyCodeChallenge(verifier1, challenge2);
         expect(isValid).toBe(false);
      });
   });

   describe('generateRSAKeyPair', () => {
      test('should generate RSA key pair with valid PEM format', () => {
         const { privateKey, publicKey } = CryptoUtils.generateRSAKeyPair();

         expect(privateKey).toBeDefined();
         expect(publicKey).toBeDefined();
         expect(typeof privateKey).toBe('string');
         expect(typeof publicKey).toBe('string');

         expect(privateKey).toContain('BEGIN');
         expect(privateKey).toContain('PRIVATE KEY');
         expect(privateKey).toContain('END');
         expect(publicKey).toContain('BEGIN');
         expect(publicKey).toContain('PUBLIC KEY');
         expect(publicKey).toContain('END');
      });

      test('should generate unique key pairs', () => {
         const keyPair1 = CryptoUtils.generateRSAKeyPair();
         const keyPair2 = CryptoUtils.generateRSAKeyPair();

         expect(keyPair1.privateKey).not.toBe(keyPair2.privateKey);
         expect(keyPair1.publicKey).not.toBe(keyPair2.publicKey);
      });

      test('should return valid PEM structure', () => {
         const { privateKey, publicKey } = CryptoUtils.generateRSAKeyPair();

         const privateKeyLines = privateKey.split('\n');
         const publicKeyLines = publicKey.split('\n');

         expect(privateKeyLines[0]).toContain('BEGIN');
         expect(privateKeyLines[privateKeyLines.length - 2]).toContain('END');
         expect(publicKeyLines[0]).toContain('BEGIN');
         expect(publicKeyLines[publicKeyLines.length - 2]).toContain('END');
      });
   });

   describe('pemToJWK', () => {
      test('should convert PEM to JWK with correct structure', () => {
         const { publicKey } = CryptoUtils.generateRSAKeyPair();
         const kid = 'test-key-123';
         const jwk = CryptoUtils.pemToJWK(publicKey, kid);

         expect(jwk).toBeDefined();
         expect(jwk.kid).toBe(kid);
         expect(jwk.kty).toBe('RSA');
         expect(jwk.use).toBe('sig');
         expect(jwk.alg).toBe('RS256');
         expect(jwk.n).toBeDefined();
         expect(jwk.e).toBeDefined();
      });

      test('should include all required JWK fields', () => {
         const { publicKey } = CryptoUtils.generateRSAKeyPair();
         const jwk = CryptoUtils.pemToJWK(publicKey, 'test-key');

         expect(jwk).toHaveProperty('kid');
         expect(jwk).toHaveProperty('kty');
         expect(jwk).toHaveProperty('use');
         expect(jwk).toHaveProperty('alg');
         expect(jwk).toHaveProperty('n');
         expect(jwk).toHaveProperty('e');
      });

      test('should use provided key ID', () => {
         const { publicKey } = CryptoUtils.generateRSAKeyPair();
         const kid1 = 'key-1';
         const kid2 = 'key-2';

         const jwk1 = CryptoUtils.pemToJWK(publicKey, kid1);
         const jwk2 = CryptoUtils.pemToJWK(publicKey, kid2);

         expect(jwk1.kid).toBe(kid1);
         expect(jwk2.kid).toBe(kid2);
      });
   });

   describe('generateJWKS', () => {
      test('should generate JWKS with proper format', () => {
         const { publicKey } = CryptoUtils.generateRSAKeyPair();
         const kid = 'test-key-123';
         const jwks = CryptoUtils.generateJWKS(publicKey, kid);

         expect(jwks).toBeDefined();
         expect(jwks).toHaveProperty('keys');
         expect(Array.isArray(jwks.keys)).toBe(true);
         expect(jwks.keys.length).toBe(1);
      });

      test('should include valid JWK in keys array', () => {
         const { publicKey } = CryptoUtils.generateRSAKeyPair();
         const kid = 'test-key-123';
         const jwks = CryptoUtils.generateJWKS(publicKey, kid);

         expect(jwks.keys[0]).toBeDefined();
         if (jwks.keys[0]) {
            expect(jwks.keys[0].kid).toBe(kid);
            expect(jwks.keys[0].kty).toBe('RSA');
            expect(jwks.keys[0].use).toBe('sig');
            expect(jwks.keys[0].alg).toBe('RS256');
         }
      });

      test('should generate complete JWKS structure', () => {
         const { publicKey } = CryptoUtils.generateRSAKeyPair();
         const jwks = CryptoUtils.generateJWKS(publicKey, 'key-id');

         expect(jwks.keys).toHaveLength(1);
         if (jwks.keys[0]) {
            expect(jwks.keys[0]).toHaveProperty('kid');
            expect(jwks.keys[0]).toHaveProperty('kty');
            expect(jwks.keys[0]).toHaveProperty('use');
            expect(jwks.keys[0]).toHaveProperty('alg');
            expect(jwks.keys[0]).toHaveProperty('n');
            expect(jwks.keys[0]).toHaveProperty('e');
         }
      });
   });
});

describe('TokenUtils', () => {
   describe('generateToken', () => {
      test('should generate unique tokens', () => {
         const token1 = TokenUtils.generateToken();
         const token2 = TokenUtils.generateToken();

         expect(token1).toBeDefined();
         expect(token2).toBeDefined();
         expect(token1).not.toBe(token2);
      });

      test('should generate tokens with correct length', () => {
         const token = TokenUtils.generateToken();

         expect(token).toBeDefined();
         expect(token.length).toBe(64); // 32 bytes = 64 hex chars
      });

      test('should generate hex-formatted tokens', () => {
         const token = TokenUtils.generateToken();

         expect(token).toMatch(/^[0-9a-f]{64}$/);
      });
   });

   describe('generateEmailVerificationToken', () => {
      test('should generate email verification token', () => {
         const token = TokenUtils.generateEmailVerificationToken();

         expect(token).toBeDefined();
         expect(token.length).toBe(64);
      });

      test('should generate unique tokens for each call', () => {
         const token1 = TokenUtils.generateEmailVerificationToken();
         const token2 = TokenUtils.generateEmailVerificationToken();

         expect(token1).not.toBe(token2);
      });

      test('should generate hex-formatted token', () => {
         const token = TokenUtils.generateEmailVerificationToken();
         expect(token).toMatch(/^[0-9a-f]{64}$/);
      });
   });

   describe('generatePasswordResetToken', () => {
      test('should generate password reset token', () => {
         const token = TokenUtils.generatePasswordResetToken();

         expect(token).toBeDefined();
         expect(token.length).toBe(64);
      });

      test('should generate unique tokens for each call', () => {
         const token1 = TokenUtils.generatePasswordResetToken();
         const token2 = TokenUtils.generatePasswordResetToken();

         expect(token1).not.toBe(token2);
      });

      test('should generate hex-formatted token', () => {
         const token = TokenUtils.generatePasswordResetToken();
         expect(token).toMatch(/^[0-9a-f]{64}$/);
      });
   });

   describe('generateRefreshToken', () => {
      test('should generate refresh token', () => {
         const token = TokenUtils.generateRefreshToken();

         expect(token).toBeDefined();
         expect(token.length).toBe(64);
      });

      test('should generate unique tokens for each call', () => {
         const token1 = TokenUtils.generateRefreshToken();
         const token2 = TokenUtils.generateRefreshToken();

         expect(token1).not.toBe(token2);
      });

      test('should generate hex-formatted token', () => {
         const token = TokenUtils.generateRefreshToken();
         expect(token).toMatch(/^[0-9a-f]{64}$/);
      });
   });

   describe('token consistency across different types', () => {
      test('should generate different token types independently', () => {
         const emailToken = TokenUtils.generateEmailVerificationToken();
         const resetToken = TokenUtils.generatePasswordResetToken();
         const refreshToken = TokenUtils.generateRefreshToken();

         expect(emailToken).not.toBe(resetToken);
         expect(emailToken).not.toBe(refreshToken);
         expect(resetToken).not.toBe(refreshToken);
      });
   });
});

