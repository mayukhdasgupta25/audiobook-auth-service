import { Request, Response } from 'express';

// Mock dependencies
jest.mock('../../src/services/FileUrlService', () => ({
   fileUrlService: {
      processUploadedImageFile: jest.fn().mockResolvedValue('/uploads/images/authors/image-1.jpg'),
   },
}));

jest.mock('../../src/services/auth', () => ({
   authService: {
      register: jest.fn(),
      login: jest.fn(),
      mobileLogin: jest.fn(),
      refreshToken: jest.fn(),
      logout: jest.fn(),
      verifyEmail: jest.fn(),
      verifyRegistrationOTP: jest.fn(),
      forgotPassword: jest.fn(),
      resetPassword: jest.fn(),
      changePassword: jest.fn(),
      getUserById: jest.fn(),
   },
}));

jest.mock('../../src/services/redis', () => ({
   redisService: {
      revokeToken: jest.fn(),
      revokeAllUserTokens: jest.fn(),
   },
}));

jest.mock('../../src/utils/crypto', () => ({
   JWTUtils: {
      decodeToken: jest.fn(),
   },
}));

// Import after mocks
import { authController } from '../../src/controllers/auth';
import { authService } from '../../src/services/auth';
import { fileUrlService } from '../../src/services/FileUrlService';
import { redisService } from '../../src/services/redis';
import { JWTUtils } from '../../src/utils/crypto';

describe('AuthController', () => {
   let mockRequest: Partial<Request>;
   let mockResponse: Partial<Response>;
   let mockStatus: jest.Mock;
   let mockJson: jest.Mock;
   let mockCookie: jest.Mock;
   let mockClearCookie: jest.Mock;

   beforeEach(() => {
      jest.clearAllMocks();

      // Setup mock response
      mockStatus = jest.fn().mockReturnThis();
      mockJson = jest.fn().mockReturnThis();
      mockCookie = jest.fn().mockReturnThis();
      mockClearCookie = jest.fn().mockReturnThis();

      mockResponse = {
         status: mockStatus,
         json: mockJson,
         cookie: mockCookie,
         clearCookie: mockClearCookie,
      };

      mockRequest = {
         body: {},
         cookies: {},
         headers: {},
      };
   });

   describe('getCsrfToken', () => {
      test('should set csrfToken cookie and return token in body', async () => {
         await authController.getCsrfToken(mockRequest as Request, mockResponse as Response);

         expect(mockCookie).toHaveBeenCalledWith(
            'csrfToken',
            expect.stringMatching(/^[a-f0-9]{64}$/),
            {
               httpOnly: true,
               secure: false,
               sameSite: 'lax',
               path: '/',
               maxAge: 24 * 60 * 60 * 1000,
            },
         );
         expect(mockJson).toHaveBeenCalledWith({
            csrfToken: expect.stringMatching(/^[a-f0-9]{64}$/),
         });
         const cookieToken = mockCookie.mock.calls[0][1];
         const jsonToken = mockJson.mock.calls[0][0].csrfToken;
         expect(cookieToken).toBe(jsonToken);
      });
   });

   describe('register', () => {
      const validPassword = 'Password1!';

      test('should register successfully and return 201', async () => {
         const mockUser = { id: 'user-123', email: 'test@example.com' };
         (authService.register as jest.Mock).mockResolvedValue({
            user: mockUser,
            otpSent: true,
         });

         mockRequest.body = {
            email: 'test@example.com',
            password: validPassword,
            confirmPassword: validPassword,
            address: '456 Oak Ave',
            contact: '+919123456789',
         };

         await authController.register(mockRequest as Request, mockResponse as Response);

         expect(authService.register).toHaveBeenCalledWith({
            email: 'test@example.com',
            password: validPassword,
            role: 'LISTENER',
            address: '456 Oak Ave',
            contact: '+919123456789',
         });
         expect(mockStatus).toHaveBeenCalledWith(201);
         expect(mockJson).toHaveBeenCalledWith({
            message: 'User registered successfully. Please check your email for OTP verification.',
            user: mockUser,
            otpSent: true,
         });
      });

      test('should reject JSON author registration', async () => {
         mockRequest.body = {
            type: 'AUTHOR',
            email: 'author@example.com',
            password: validPassword,
            confirmPassword: validPassword,
            firstName: 'Jane',
            lastName: 'Doe',
            address: '123 Main St',
         };

         await authController.register(mockRequest as Request, mockResponse as Response);

         expect(authService.register).not.toHaveBeenCalled();
         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(mockJson).toHaveBeenCalledWith(
            expect.objectContaining({
               error: 'Author registration requires multipart/form-data',
               code: 'VALIDATION_ERROR',
            }),
         );
      });

      test('should register author from multipart payload with profile image', async () => {
         const mockUser = { id: 'author-123', email: 'author@example.com' };
         (authService.register as jest.Mock).mockResolvedValue({
            user: mockUser,
            otpSent: true,
         });

         mockRequest.headers = { 'content-type': 'multipart/form-data; boundary=test' };
         mockRequest.body = {
            type: 'AUTHOR',
            email: 'author@example.com',
            password: validPassword,
            confirmPassword: validPassword,
            firstName: 'Jane',
            lastName: 'Doe',
            address: '123 Main St',
         };
         (mockRequest as Request & { profileImageFile?: Express.Multer.File }).profileImageFile = {
            path: './src/uploads/images/authors/image-1.jpg',
            mimetype: 'image/jpeg',
         } as Express.Multer.File;

         await authController.register(mockRequest as Request, mockResponse as Response);

         expect(fileUrlService.processUploadedImageFile).toHaveBeenCalledWith(
            './src/uploads/images/authors/image-1.jpg',
            'uploads/images/authors',
            'image/jpeg',
            'profile',
         );
         expect(authService.register).toHaveBeenCalledWith({
            type: 'AUTHOR',
            email: 'author@example.com',
            password: validPassword,
            role: 'AUTHOR',
            firstName: 'Jane',
            lastName: 'Doe',
            address: '123 Main St',
            profileImage: '/uploads/images/authors/image-1.jpg',
         });
         expect(mockStatus).toHaveBeenCalledWith(201);
      });

      test('should handle duplicate email and return 400', async () => {
         (authService.register as jest.Mock).mockRejectedValue(
            new Error('User with this email already exists')
         );

         mockRequest.body = {
            email: 'existing@example.com',
            password: validPassword,
            confirmPassword: validPassword,
            address: '456 Oak Ave',
            contact: '+919123456789',
         };

         await authController.register(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(mockJson).toHaveBeenCalledWith({
            error: 'User with this email already exists',
         });
      });

      test('should handle generic registration errors', async () => {
         (authService.register as jest.Mock).mockRejectedValue(new Error('Database error'));

         mockRequest.body = {
            email: 'test@example.com',
            password: validPassword,
            confirmPassword: validPassword,
            address: '456 Oak Ave',
            contact: '+919123456789',
         };

         await authController.register(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(mockJson).toHaveBeenCalledWith({ error: 'Database error' });
      });
   });

   describe('login', () => {
      test('should login with browser client and set cookie', async () => {
         const mockAuthResponse = {
            accessToken: 'access-token',
            user: { id: 'user-123', email: 'test@example.com' },
         };
         (authService.login as jest.Mock).mockResolvedValue({
            ...mockAuthResponse,
            refreshToken: 'refresh-token',
         });

         mockRequest.body = {
            email: 'test@example.com',
            password: 'password123',
            clientType: 'browser',
            device: { deviceId: 'device-uuid-1' },
         };

         await authController.login(mockRequest as Request, mockResponse as Response);

         expect(authService.login).toHaveBeenCalledWith(
            expect.objectContaining({
               email: 'test@example.com',
               password: 'password123',
               clientType: 'browser',
               device: { deviceId: 'device-uuid-1' },
            }),
         );
         expect(mockCookie).toHaveBeenCalledWith('refreshToken', 'refresh-token', {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            path: '/',
            maxAge: 7 * 24 * 60 * 60 * 1000,
         });
         expect(mockJson).toHaveBeenCalledWith({
            message: 'Login successful',
            accessToken: 'access-token',
            user: { id: 'user-123', email: 'test@example.com' },
         });
      });

      test('should login with mobile client and return token in body', async () => {
         const mockAuthResponse = {
            accessToken: 'access-token',
            refreshToken: 'refresh-token',
            user: { id: 'user-123', email: 'test@example.com' },
         };
         (authService.login as jest.Mock).mockResolvedValue(mockAuthResponse);

         mockRequest.body = {
            email: 'test@example.com',
            password: 'password123',
            clientType: 'mobile',
            device: { deviceId: 'device-uuid-1' },
         };

         await authController.login(mockRequest as Request, mockResponse as Response);

         expect(mockCookie).not.toHaveBeenCalled();
         expect(mockJson).toHaveBeenCalledWith({
            message: 'Login successful',
            ...mockAuthResponse,
         });
      });

      test('should handle invalid credentials and return 401', async () => {
         (authService.login as jest.Mock).mockRejectedValue(
            new Error('Invalid email or password')
         );

         mockRequest.body = {
            email: 'test@example.com',
            password: 'wrong',
            device: { deviceId: 'device-uuid-1' },
         };

         await authController.login(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(401);
         expect(mockJson).toHaveBeenCalledWith({
            error: 'Invalid email or password',
         });
      });

      test('should return 400 when deviceId is missing', async () => {
         mockRequest.body = { email: 'test@example.com', password: 'password123' };

         await authController.login(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(mockJson).toHaveBeenCalledWith(
            expect.objectContaining({ code: 'DEVICE_ID_REQUIRED' }),
         );
         expect(authService.login).not.toHaveBeenCalled();
      });
   });

   describe('verifyRegistrationOTP', () => {
      test('should allow author verification without device', async () => {
         const mockAuthResponse = {
            accessToken: 'access-token',
            refreshToken: 'refresh-token',
            user: { id: 'author-1', email: 'author@example.com' },
         };
         (authService.verifyRegistrationOTP as jest.Mock).mockResolvedValue(mockAuthResponse);

         mockRequest.body = {
            email: 'author@example.com',
            otp: '123456',
            type: 'author',
         };

         await authController.verifyRegistrationOTP(mockRequest as Request, mockResponse as Response);

         expect(authService.verifyRegistrationOTP).toHaveBeenCalledWith(
            expect.objectContaining({
               email: 'author@example.com',
               otp: '123456',
               type: 'author',
               device: undefined,
            }),
         );
         expect(mockJson).toHaveBeenCalledWith(
            expect.objectContaining({
               accessToken: 'access-token',
               refreshToken: 'refresh-token',
            }),
         );
      });

      test('should allow organization verification without device', async () => {
         (authService.verifyRegistrationOTP as jest.Mock).mockResolvedValue({
            accessToken: 'access-token',
            refreshToken: 'refresh-token',
            user: { id: 'org-1', email: 'org@example.com' },
         });

         mockRequest.body = {
            email: 'org@example.com',
            otp: '123456',
            type: 'organization',
         };

         await authController.verifyRegistrationOTP(mockRequest as Request, mockResponse as Response);

         expect(authService.verifyRegistrationOTP).toHaveBeenCalledWith(
            expect.objectContaining({ type: 'organization', device: undefined }),
         );
      });

      test('should return 400 when device is missing for non-author types', async () => {
         mockRequest.body = {
            email: 'user@example.com',
            otp: '123456',
            type: 'user',
         };

         await authController.verifyRegistrationOTP(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(mockJson).toHaveBeenCalledWith(
            expect.objectContaining({ code: 'DEVICE_ID_REQUIRED' }),
         );
         expect(authService.verifyRegistrationOTP).not.toHaveBeenCalled();
      });

      test('should return 400 when device is missing and type is omitted', async () => {
         mockRequest.body = {
            email: 'user@example.com',
            otp: '123456',
         };

         await authController.verifyRegistrationOTP(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(mockJson).toHaveBeenCalledWith(
            expect.objectContaining({ code: 'DEVICE_ID_REQUIRED' }),
         );
         expect(authService.verifyRegistrationOTP).not.toHaveBeenCalled();
      });
   });

   describe('refreshToken', () => {
      test('should refresh token from cookie (browser)', async () => {
         const mockAuthResponse = {
            accessToken: 'new-access-token',
            refreshToken: 'new-refresh-token',
            user: { id: 'user-123', email: 'test@example.com' },
         };
         (authService.refreshToken as jest.Mock).mockResolvedValue(mockAuthResponse);

         mockRequest.cookies = { refreshToken: 'old-refresh-token' };

         await authController.refreshToken(mockRequest as Request, mockResponse as Response);

         expect(authService.refreshToken).toHaveBeenCalledWith({
            refreshToken: 'old-refresh-token',
         });
         expect(mockCookie).toHaveBeenCalledWith('refreshToken', 'new-refresh-token', {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            path: '/',
            maxAge: 7 * 24 * 60 * 60 * 1000,
         });
         expect(mockJson).toHaveBeenCalledWith({
            message: 'Token refreshed successfully',
            ...mockAuthResponse,
         });
      });

      test('should refresh token from body (mobile)', async () => {
         const mockAuthResponse = {
            accessToken: 'new-access-token',
            refreshToken: 'new-refresh-token',
            user: { id: 'user-123', email: 'test@example.com' },
         };
         (authService.refreshToken as jest.Mock).mockResolvedValue(mockAuthResponse);

         mockRequest.body = { refreshToken: 'token-from-body' };

         await authController.refreshToken(mockRequest as Request, mockResponse as Response);

         expect(authService.refreshToken).toHaveBeenCalledWith({
            refreshToken: 'token-from-body',
         });
         expect(mockJson).toHaveBeenCalledWith({
            message: 'Token refreshed successfully',
            ...mockAuthResponse,
         });
      });

      test('should return 401 when no refresh token provided', async () => {
         await authController.refreshToken(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(401);
         expect(mockJson).toHaveBeenCalledWith({ error: 'Refresh token required' });
      });

      test('should handle invalid token and return 401', async () => {
         (authService.refreshToken as jest.Mock).mockRejectedValue(
            new Error('Invalid or expired refresh token')
         );

         mockRequest.body = { refreshToken: 'invalid-token' };

         await authController.refreshToken(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(401);
         expect(mockJson).toHaveBeenCalledWith({
            error: 'Invalid or expired refresh token',
         });
      });
   });

   describe('logout', () => {
      const clearRefreshTokenCookieOptions = {
         path: '/',
         secure: false,
         sameSite: 'lax' as const,
      };

      test('should logout and clear cookie', async () => {
         mockRequest.cookies = { refreshToken: 'refresh-token' };

         await authController.logout(mockRequest as Request, mockResponse as Response);

         expect(authService.logout).toHaveBeenCalledWith('refresh-token');
         expect(mockClearCookie).toHaveBeenCalledWith('refreshToken', clearRefreshTokenCookieOptions);
         expect(mockJson).toHaveBeenCalledWith({ message: 'Logout successful' });
      });

      test('should logout from body token (mobile)', async () => {
         mockRequest.body = { refreshToken: 'mobile-token' };

         await authController.logout(mockRequest as Request, mockResponse as Response);

         expect(authService.logout).toHaveBeenCalledWith('mobile-token');
         expect(mockClearCookie).toHaveBeenCalledWith('refreshToken', clearRefreshTokenCookieOptions);
      });

      test('should handle logout without token gracefully', async () => {
         await authController.logout(mockRequest as Request, mockResponse as Response);

         expect(mockClearCookie).toHaveBeenCalledWith('refreshToken', clearRefreshTokenCookieOptions);
         expect(mockJson).toHaveBeenCalledWith({ message: 'Logout successful' });
      });
   });

   describe('verifyEmail', () => {
      test('should verify email successfully', async () => {
         mockRequest.body = { token: 'verification-token' };

         await authController.verifyEmail(mockRequest as Request, mockResponse as Response);

         expect(authService.verifyEmail).toHaveBeenCalledWith({ token: 'verification-token' });
         expect(mockJson).toHaveBeenCalledWith({ message: 'Email verified successfully' });
      });

      test('should handle invalid token and return 400', async () => {
         (authService.verifyEmail as jest.Mock).mockRejectedValue(
            new Error('Invalid or expired verification token')
         );

         mockRequest.body = { token: 'invalid-token' };

         await authController.verifyEmail(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(mockJson).toHaveBeenCalledWith({
            error: 'Invalid or expired verification token',
         });
      });
   });

   describe('forgotPassword', () => {
      test('should send password reset OTP', async () => {
         mockRequest.body = { email: 'test@example.com' };

         await authController.forgotPassword(mockRequest as Request, mockResponse as Response);

         expect(authService.forgotPassword).toHaveBeenCalledWith({ email: 'test@example.com' });
         expect(mockJson).toHaveBeenCalledWith({
            message: 'If the email exists, an OTP has been sent to your email',
         });
      });
   });

   describe('resetPassword', () => {
      test('should reset password successfully', async () => {
         mockRequest.body = {
            token: 'reset-token',
            newPassword: 'newPassword123',
         };

         await authController.resetPassword(mockRequest as Request, mockResponse as Response);

         expect(authService.resetPassword).toHaveBeenCalledWith({
            token: 'reset-token',
            newPassword: 'newPassword123',
         });
         expect(mockJson).toHaveBeenCalledWith({ message: 'Password reset successfully' });
      });

      test('should handle invalid token and return 400', async () => {
         (authService.resetPassword as jest.Mock).mockRejectedValue(
            new Error('Invalid or expired reset token')
         );

         mockRequest.body = { token: 'invalid', newPassword: 'newpass' };

         await authController.resetPassword(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(mockJson).toHaveBeenCalledWith({
            error: 'Invalid or expired reset token',
         });
      });
   });

   describe('changePassword', () => {
      test('should change password successfully', async () => {
         mockRequest.body = {
            currentPassword: 'current',
            newPassword: 'newpass',
         };
         (mockRequest as any).user = { id: 'user-123' };

         await authController.changePassword(mockRequest as Request, mockResponse as Response);

         expect(authService.changePassword).toHaveBeenCalledWith('user-123', {
            currentPassword: 'current',
            newPassword: 'newpass',
         });
         expect(mockJson).toHaveBeenCalledWith({ message: 'Password changed successfully' });
      });

      test('should handle wrong current password and return 400', async () => {
         (authService.changePassword as jest.Mock).mockRejectedValue(
            new Error('Current password is incorrect')
         );

         mockRequest.body = {
            currentPassword: 'wrong',
            newPassword: 'newpass',
         };
         (mockRequest as any).user = { id: 'user-123' };

         await authController.changePassword(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(mockJson).toHaveBeenCalledWith({
            error: 'Current password is incorrect',
         });
      });
   });

   describe('getMe', () => {
      test('should return current user info', async () => {
         const mockUser = { id: 'user-123', email: 'test@example.com' };
         (authService.getUserById as jest.Mock).mockResolvedValue(mockUser);

         (mockRequest as any).user = { id: 'user-123' };

         await authController.getMe(mockRequest as Request, mockResponse as Response);

         expect(authService.getUserById).toHaveBeenCalledWith('user-123');
         expect(mockJson).toHaveBeenCalledWith({ user: mockUser });
      });

      test('should return 404 when user not found', async () => {
         (authService.getUserById as jest.Mock).mockResolvedValue(null);

         (mockRequest as any).user = { id: 'user-123' };

         await authController.getMe(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(404);
         expect(mockJson).toHaveBeenCalledWith({ error: 'User not found' });
      });
   });

   describe('revokeToken', () => {
      test('should revoke token successfully', async () => {
         (JWTUtils.decodeToken as jest.Mock).mockReturnValue({
            sub: 'user-123',
            jti: 'token-jti',
         });

         mockRequest.body = { jti: 'token-jti' };
         (mockRequest as any).token = 'jwt-token';

         await authController.revokeToken(mockRequest as Request, mockResponse as Response);

         expect(JWTUtils.decodeToken).toHaveBeenCalledWith('jwt-token');
         expect(redisService.revokeToken).toHaveBeenCalledWith(
            'token-jti',
            'user-123',
            'Admin revocation'
         );
         expect(mockJson).toHaveBeenCalledWith({ message: 'Token revoked successfully' });
      });

      test('should return 400 when token is invalid', async () => {
         (JWTUtils.decodeToken as jest.Mock).mockReturnValue(null);

         mockRequest.body = { jti: 'token-jti' };
         (mockRequest as any).token = 'invalid-token';

         await authController.revokeToken(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(mockJson).toHaveBeenCalledWith({ error: 'Invalid token' });
      });
   });

   describe('emergencyRevoke', () => {
      test('should revoke all user tokens successfully', async () => {
         mockRequest.body = { userId: 'user-123' };

         await authController.emergencyRevoke(mockRequest as Request, mockResponse as Response);

         expect(redisService.revokeAllUserTokens).toHaveBeenCalledWith(
            'user-123',
            'Emergency revocation by admin'
         );
         expect(mockJson).toHaveBeenCalledWith({
            message: 'All user tokens revoked successfully',
         });
      });

      test('should return 400 when userId is missing', async () => {
         mockRequest.body = {};

         await authController.emergencyRevoke(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(mockJson).toHaveBeenCalledWith({ error: 'User ID required' });
      });
   });
});

