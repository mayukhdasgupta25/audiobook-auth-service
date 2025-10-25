import { PasswordUtils, JWTUtils, CryptoUtils } from '../src/utils/crypto';
import { authService } from '../src/services/auth';

describe('Password Utils', () => {
   test('should hash and verify password correctly', async () => {
      const password = 'testPassword123';
      const hash = await PasswordUtils.hashPassword(password);

      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);

      const isValid = await PasswordUtils.verifyPassword(password, hash);
      expect(isValid).toBe(true);

      const isInvalid = await PasswordUtils.verifyPassword('wrongPassword', hash);
      expect(isInvalid).toBe(false);
   });
});

describe('Crypto Utils', () => {
   test('should generate secure tokens', () => {
      const token1 = CryptoUtils.generateSecureToken();
      const token2 = CryptoUtils.generateSecureToken();

      expect(token1).toBeDefined();
      expect(token2).toBeDefined();
      expect(token1).not.toBe(token2);
      expect(token1).toHaveLength(64); // 32 bytes = 64 hex chars
   });

   test('should generate and verify PKCE codes', () => {
      const codeVerifier = CryptoUtils.generateCodeVerifier();
      const codeChallenge = CryptoUtils.generateCodeChallenge(codeVerifier);

      expect(codeVerifier).toBeDefined();
      expect(codeChallenge).toBeDefined();
      expect(codeVerifier).not.toBe(codeChallenge);

      const isValid = CryptoUtils.verifyCodeChallenge(codeVerifier, codeChallenge);
      expect(isValid).toBe(true);

      const isInvalid = CryptoUtils.verifyCodeChallenge(codeVerifier, 'wrongChallenge');
      expect(isInvalid).toBe(false);
   });
});

describe('JWT Utils', () => {
   test('should generate and verify access token', () => {
      const payload = {
         sub: 'user123',
         email: 'test@example.com',
         role: 'USER' as const,
      };

      const token = JWTUtils.generateAccessToken(payload);
      expect(token).toBeDefined();

      const decoded = JWTUtils.decodeToken(token);
      expect(decoded).toBeDefined();
      expect(decoded?.sub).toBe(payload.sub);
      expect(decoded?.email).toBe(payload.email);
      expect(decoded?.role).toBe(payload.role);
   });
});

describe('Auth Service', () => {
   test('should register user successfully', async () => {
      const mockUser = {
         id: 'user123',
         email: 'test@example.com',
         password: 'hashedPassword',
         role: 'USER' as const,
         emailVerified: false,
         createdAt: new Date(),
         updatedAt: new Date(),
      };

      const mockVerificationToken = {
         id: 'token123',
         token: 'verificationToken',
         userId: 'user123',
         expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
         createdAt: new Date(),
         used: false,
      };

      // Mock Prisma calls
      const mockPrisma = require('@prisma/client').PrismaClient;
      const mockPrismaInstance = new mockPrisma();

      mockPrismaInstance.user.findUnique.mockResolvedValue(null);
      mockPrismaInstance.user.create.mockResolvedValue(mockUser);
      mockPrismaInstance.emailVerificationToken.create.mockResolvedValue(mockVerificationToken);

      const result = await authService.register({
         email: 'test@example.com',
         password: 'password123',
      });

      expect(result.user.email).toBe('test@example.com');
      expect(result.verificationToken).toBeDefined();
   });
});
