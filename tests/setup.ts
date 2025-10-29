// Test setup file
// IMPORTANT: Set environment variables BEFORE any imports that depend on config
// This prevents env validation errors during test initialization

import forge from 'node-forge';

// Set NODE_ENV to test first
process.env['NODE_ENV'] = 'test';

// Generate RSA key pair for JWT testing (before importing anything that uses config)
const keypair = forge.pki.rsa.generateKeyPair(2048);
const testKeys = {
   privateKey: forge.pki.privateKeyToPem(keypair.privateKey),
   publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
};

// Set all required environment variables before any config-dependent imports
process.env['DATABASE_URL'] = 'postgresql://test:test@localhost:5432/test_auth_service';
process.env['REDIS_URL'] = 'redis://localhost:6379';
process.env['RABBITMQ_URL'] = 'amqp://localhost:5672';
process.env['JWT_PRIVATE_KEY'] = testKeys.privateKey;
process.env['JWT_PUBLIC_KEY'] = testKeys.publicKey;
process.env['JWT_KEY_ID'] = 'test-key-1';
process.env['JWT_ISSUER'] = 'test-auth-service';

// Now safe to import modules that depend on config
// (No imports needed here - tests can import what they need)

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
