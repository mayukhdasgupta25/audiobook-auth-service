// Test setup file
import { CryptoUtils } from '../src/utils/crypto';

// Mock Prisma client for tests
jest.mock('@prisma/client', () => ({
   PrismaClient: jest.fn().mockImplementation(() => ({
      user: {
         findUnique: jest.fn(),
         create: jest.fn(),
         update: jest.fn(),
         findMany: jest.fn(),
      },
      refreshToken: {
         findUnique: jest.fn(),
         create: jest.fn(),
         update: jest.fn(),
         updateMany: jest.fn(),
      },
      emailVerificationToken: {
         findUnique: jest.fn(),
         create: jest.fn(),
         update: jest.fn(),
      },
      passwordResetToken: {
         findUnique: jest.fn(),
         create: jest.fn(),
         update: jest.fn(),
      },
   })),
   Role: {
      USER: 'USER',
      ADMIN: 'ADMIN',
   },
}));

// Mock Redis service
jest.mock('../src/services/redis', () => ({
   redisService: {
      connect: jest.fn(),
      disconnect: jest.fn(),
      revokeToken: jest.fn(),
      isTokenRevoked: jest.fn().mockResolvedValue(false),
      hasEmergencyRevoke: jest.fn().mockResolvedValue(false),
      storePKCESession: jest.fn(),
      getPKCESession: jest.fn(),
      deletePKCESession: jest.fn(),
      healthCheck: jest.fn().mockResolvedValue(true),
   },
}));

// Generate RSA key pair for JWT testing
const testKeys = CryptoUtils.generateRSAKeyPair();

// Set test environment
process.env['NODE_ENV'] = 'test';
process.env['DATABASE_URL'] = 'postgresql://test:test@localhost:5432/test_auth_service';
process.env['REDIS_URL'] = 'redis://localhost:6379';
process.env['JWT_PRIVATE_KEY'] = testKeys.privateKey;
process.env['JWT_PUBLIC_KEY'] = testKeys.publicKey;
process.env['JWT_KEY_ID'] = 'test-key-1';
process.env['JWT_ISSUER'] = 'test-auth-service';
