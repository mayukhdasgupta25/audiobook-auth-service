import { Request, Response } from 'express';
import { userDeviceController } from '../../src/controllers/UserDeviceController';
import { DEVICE_REMOVAL_OTP_GENERIC_MESSAGE } from '../../src/services/userDevice';

jest.mock('../../src/services/userDevice', () => ({
   userDeviceService: {
      listDevices: jest.fn(),
      getDeviceLimitInfo: jest.fn(),
      requestDeviceRemovalOtp: jest.fn(),
      resendDeviceRemovalOtp: jest.fn(),
      removeDeviceWithOtp: jest.fn(),
   },
   DEVICE_REMOVAL_OTP_GENERIC_MESSAGE:
      'If the account and device are eligible, an OTP has been sent to your email.',
}));

import { userDeviceService } from '../../src/services/userDevice';

describe('UserDeviceController', () => {
   let mockRequest: Partial<Request>;
   let mockResponse: Partial<Response>;
   let mockStatus: jest.Mock;
   let mockJson: jest.Mock;

   beforeEach(() => {
      jest.clearAllMocks();
      mockStatus = jest.fn().mockReturnThis();
      mockJson = jest.fn().mockReturnThis();
      mockResponse = { status: mockStatus, json: mockJson };
      mockRequest = { body: {}, params: {}, headers: {} };
   });

   describe('requestRemovalOtp', () => {
      it('returns generic 200 message without requiring auth', async () => {
         mockRequest.body = { email: 'user@example.com', deviceId: 'dev-row-1' };

         await userDeviceController.requestRemovalOtp(
            mockRequest as Request,
            mockResponse as Response,
         );

         expect(userDeviceService.requestDeviceRemovalOtp).toHaveBeenCalledWith(
            'user@example.com',
            'dev-row-1',
         );
         expect(mockStatus).toHaveBeenCalledWith(200);
         expect(mockJson).toHaveBeenCalledWith({ message: DEVICE_REMOVAL_OTP_GENERIC_MESSAGE });
      });

      it('returns 400 when email or deviceId is missing', async () => {
         mockRequest.body = { email: 'user@example.com' };

         await userDeviceController.requestRemovalOtp(
            mockRequest as Request,
            mockResponse as Response,
         );

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(userDeviceService.requestDeviceRemovalOtp).not.toHaveBeenCalled();
      });
   });

   describe('resendRemovalOtp', () => {
      it('returns 200 when resend succeeds', async () => {
         mockRequest.body = { email: 'user@example.com', deviceId: 'dev-row-1' };

         await userDeviceController.resendRemovalOtp(
            mockRequest as Request,
            mockResponse as Response,
         );

         expect(userDeviceService.resendDeviceRemovalOtp).toHaveBeenCalledWith(
            'user@example.com',
            'dev-row-1',
         );
         expect(mockStatus).toHaveBeenCalledWith(200);
      });

      it('returns 429 when resend is within cooldown', async () => {
         mockRequest.body = { email: 'user@example.com', deviceId: 'dev-row-1' };
         const { AuthError } = await import('../../src/types');
         (userDeviceService.resendDeviceRemovalOtp as jest.Mock).mockRejectedValue(
            new AuthError('Please wait 15 seconds', 429, 'OTP_RESEND_COOLDOWN', {
               remainingSeconds: 15,
            }),
         );

         await userDeviceController.resendRemovalOtp(
            mockRequest as Request,
            mockResponse as Response,
         );

         expect(mockStatus).toHaveBeenCalledWith(429);
      });
   });

   describe('removeDevice', () => {
      it('removes device with email and otp without auth', async () => {
         mockRequest.params = { id: 'dev-row-1' };
         mockRequest.body = { email: 'user@example.com', otp: '123456' };

         await userDeviceController.removeDevice(mockRequest as Request, mockResponse as Response);

         expect(userDeviceService.removeDeviceWithOtp).toHaveBeenCalledWith(
            'user@example.com',
            '123456',
            'dev-row-1',
         );
         expect(mockStatus).toHaveBeenCalledWith(200);
      });

      it('returns 400 when otp is missing', async () => {
         mockRequest.params = { id: 'dev-row-1' };
         mockRequest.body = { email: 'user@example.com' };

         await userDeviceController.removeDevice(mockRequest as Request, mockResponse as Response);

         expect(mockStatus).toHaveBeenCalledWith(400);
         expect(userDeviceService.removeDeviceWithOtp).not.toHaveBeenCalled();
      });
   });
});
