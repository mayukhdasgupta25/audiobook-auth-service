import { Role, UserType } from '@prisma/client';

const mockPrisma = {
   user: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
   },
   refreshToken: {
      create: jest.fn(),
   },
};

jest.mock('@prisma/client', () => ({
   PrismaClient: jest.fn(() => mockPrisma),
   Role: { USER: 'USER', ADMIN: 'ADMIN', AUTHOR: 'AUTHOR' },
   UserType: { USER: 'USER', AUTHOR: 'AUTHOR' },
   OtpPurpose: {
      REGISTRATION: 'REGISTRATION',
   },
}));

jest.mock('../../src/utils/crypto', () => ({
   PasswordUtils: {
      hashPassword: jest.fn().mockResolvedValue('hashed-password'),
      verifyPassword: jest.fn(),
   },
   TokenUtils: {
      generateRefreshToken: jest.fn().mockReturnValue('refresh-token'),
   },
   JWTUtils: {
      generateAccessToken: jest.fn().mockReturnValue('access-token'),
   },
}));

jest.mock('../../src/services/redis', () => ({
   redisService: {
      setPendingAuthorRegistration: jest.fn().mockResolvedValue(undefined),
      getPendingAuthorRegistration: jest.fn(),
      deletePendingAuthorRegistration: jest.fn().mockResolvedValue(undefined),
      setPendingUserRegistration: jest.fn().mockResolvedValue(undefined),
      getPendingUserRegistration: jest.fn(),
      deletePendingUserRegistration: jest.fn().mockResolvedValue(undefined),
   },
}));

jest.mock('../../src/services/rabbitmq', () => ({
   rabbitmqService: {
      publishUserCreated: jest.fn().mockResolvedValue(undefined),
      publishAuthorCreated: jest.fn().mockResolvedValue(undefined),
   },
}));

jest.mock('../../src/services/otp', () => ({
   otpService: {
      createOTP: jest.fn().mockResolvedValue(undefined),
      verifyOTP: jest.fn().mockResolvedValue(undefined),
   },
}));

jest.mock('../../src/services/userDevice', () => ({
   userDeviceService: {
      resolveDeviceForAuth: jest.fn().mockResolvedValue({ id: 'device-1' }),
   },
}));

jest.mock('../../src/services/google-oauth', () => ({
   googleOAuthService: {
      verifyIdToken: jest.fn(),
   },
}));

import { AuthService } from '../../src/services/auth';
import { redisService } from '../../src/services/redis';
import { rabbitmqService } from '../../src/services/rabbitmq';
import { userDeviceService } from '../../src/services/userDevice';

describe('AuthService register/verify author flow', () => {
   let authService: AuthService;

   beforeEach(() => {
      jest.clearAllMocks();
      authService = new AuthService();
   });

   test('should store pending author metadata on author registration', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      mockPrisma.user.create.mockResolvedValue({
         id: 'author-user-1',
         email: 'author@example.com',
         role: Role.USER,
         type: UserType.AUTHOR,
         emailVerified: false,
         createdAt: new Date(),
         updatedAt: new Date(),
      });

      await authService.register({
         email: 'author@example.com',
         password: 'password123',
         type: 'AUTHOR',
         firstName: 'Jane',
         lastName: 'Doe',
         address: '123 Main St',
         contact: '+1-555-0100',
         profileImage: 'uploads/images/authors/image-1.jpg',
      });

      expect(redisService.setPendingAuthorRegistration).toHaveBeenCalledWith('author-user-1', {
         firstName: 'Jane',
         lastName: 'Doe',
         address: '123 Main St',
         contact: '+1-555-0100',
         profileImage: 'uploads/images/authors/image-1.jpg',
      });
   });

   test('should store pending user metadata on user registration', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      mockPrisma.user.create.mockResolvedValue({
         id: 'user-1',
         email: 'user@example.com',
         role: Role.USER,
         type: UserType.USER,
         emailVerified: false,
         createdAt: new Date(),
         updatedAt: new Date(),
      });

      await authService.register({
         email: 'user@example.com',
         password: 'password123',
         type: 'USER',
         address: '456 Oak Ave',
         contact: '+1-555-0200',
         avatar: 'uploads/images/users/avatar-1.jpg',
      });

      expect(redisService.setPendingUserRegistration).toHaveBeenCalledWith('user-1', {
         address: '456 Oak Ave',
         contact: '+1-555-0200',
         avatar: 'uploads/images/users/avatar-1.jpg',
      });
   });

   test('should publish author.created after OTP verification for author users', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({
         id: 'author-user-1',
         email: 'author@example.com',
         role: Role.USER,
         type: UserType.AUTHOR,
         emailVerified: false,
      });
      mockPrisma.user.update.mockResolvedValue({
         id: 'author-user-1',
         email: 'author@example.com',
         role: Role.USER,
         type: UserType.AUTHOR,
         emailVerified: true,
      });
      mockPrisma.refreshToken.create.mockResolvedValue({});

      (redisService.getPendingAuthorRegistration as jest.Mock).mockResolvedValue({
         firstName: 'Jane',
         lastName: 'Doe',
         address: '123 Main St',
         contact: '+1-555-0100',
         profileImage: 'uploads/images/authors/image-1.jpg',
      });

      await authService.verifyRegistrationOTP({
         email: 'author@example.com',
         otp: '123456',
         device: { deviceId: 'device-1' },
      });

      expect(rabbitmqService.publishAuthorCreated).toHaveBeenCalledWith({
         userId: 'author-user-1',
         firstName: 'Jane',
         lastName: 'Doe',
         address: '123 Main St',
         contact: '+1-555-0100',
         profileImage: 'uploads/images/authors/image-1.jpg',
      });
      expect(rabbitmqService.publishUserCreated).not.toHaveBeenCalled();
      expect(redisService.deletePendingAuthorRegistration).toHaveBeenCalledWith('author-user-1');
   });

   test('should skip device registration for author OTP verification without device', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({
         id: 'author-user-1',
         email: 'author@example.com',
         role: Role.USER,
         type: UserType.AUTHOR,
         emailVerified: false,
      });
      mockPrisma.user.update.mockResolvedValue({
         id: 'author-user-1',
         email: 'author@example.com',
         role: Role.USER,
         type: UserType.AUTHOR,
         emailVerified: true,
      });
      mockPrisma.refreshToken.create.mockResolvedValue({});

      (redisService.getPendingAuthorRegistration as jest.Mock).mockResolvedValue({
         firstName: 'Jane',
         lastName: 'Doe',
         address: '123 Main St',
      });

      await authService.verifyRegistrationOTP({
         email: 'author@example.com',
         otp: '123456',
         type: 'author',
      });

      expect(userDeviceService.resolveDeviceForAuth).not.toHaveBeenCalled();
      expect(mockPrisma.refreshToken.create).toHaveBeenCalledWith({
         data: expect.objectContaining({
            userDeviceId: null,
         }),
      });
   });

   test('should publish user.created for regular users after OTP verification', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({
         id: 'user-1',
         email: 'user@example.com',
         role: Role.USER,
         type: UserType.USER,
         emailVerified: false,
      });
      mockPrisma.user.update.mockResolvedValue({
         id: 'user-1',
         email: 'user@example.com',
         role: Role.USER,
         type: UserType.USER,
         emailVerified: true,
      });
      mockPrisma.refreshToken.create.mockResolvedValue({});

      (redisService.getPendingUserRegistration as jest.Mock).mockResolvedValue({
         address: '456 Oak Ave',
         contact: '+1-555-0200',
         avatar: 'uploads/images/users/avatar-1.jpg',
      });

      await authService.verifyRegistrationOTP({
         email: 'user@example.com',
         otp: '123456',
         firstName: 'John',
         lastName: 'Doe',
         device: { deviceId: 'device-1' },
      });

      expect(rabbitmqService.publishUserCreated).toHaveBeenCalledWith({
         userId: 'user-1',
         firstName: 'John',
         lastName: 'Doe',
         address: '456 Oak Ave',
         contact: '+1-555-0200',
         avatar: 'uploads/images/users/avatar-1.jpg',
      });
      expect(rabbitmqService.publishAuthorCreated).not.toHaveBeenCalled();
      expect(redisService.deletePendingUserRegistration).toHaveBeenCalledWith('user-1');
   });
});
