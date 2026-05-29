import { Request, Response } from 'express';

import {

   userDeviceService,

   DEVICE_REMOVAL_OTP_GENERIC_MESSAGE,

} from '../services/userDevice';

import { AuthError, AuthenticatedRequest, ValidationError } from '../types';

import type { RemoveDeviceWithOtpRequest, RequestDeviceRemovalOtpRequest } from '../types';

import { handleAuthControllerError } from '../utils/authController';



export class UserDeviceController {

   private getAuthUserId(req: Request): string {

      const authUser = (req as AuthenticatedRequest).user;

      if (!authUser?.id) {

         throw new AuthError('Authentication required', 401, 'UNAUTHORIZED');

      }

      return authUser.id;

   }



   listMyDevices = async (req: Request, res: Response): Promise<void> => {

      try {

         const userId = this.getAuthUserId(req);



         const [devices, limits] = await Promise.all([

            userDeviceService.listDevices(userId),

            userDeviceService.getDeviceLimitInfo(userId),

         ]);



         res.status(200).json({

            devices,

            limits,

         });

      } catch (error) {

         handleAuthControllerError(res, error, 'Failed to list devices');

      }

   };



   requestRemovalOtp = async (req: Request, res: Response): Promise<void> => {
      try {
         const data = this.parseRequestRemovalOtpBody(req.body);
         await userDeviceService.requestDeviceRemovalOtp(data.email, data.deviceId);

         res.status(200).json({ message: DEVICE_REMOVAL_OTP_GENERIC_MESSAGE });
      } catch (error) {
         handleAuthControllerError(res, error, 'Failed to request device removal OTP');
      }
   };

   resendRemovalOtp = async (req: Request, res: Response): Promise<void> => {
      try {
         const data = this.parseRequestRemovalOtpBody(req.body);
         await userDeviceService.resendDeviceRemovalOtp(data.email, data.deviceId);

         res.status(200).json({ message: DEVICE_REMOVAL_OTP_GENERIC_MESSAGE });
      } catch (error) {
         handleAuthControllerError(res, error, 'Failed to resend device removal OTP');
      }
   };

   removeDevice = async (req: Request, res: Response): Promise<void> => {

      try {

         const deviceRowId = req.params['id'];

         if (!deviceRowId || typeof deviceRowId !== 'string') {

            throw new AuthError('Device id is required', 400, 'VALIDATION_ERROR');

         }



         const data = this.parseRemoveDeviceWithOtpBody(req.body);

         await userDeviceService.removeDeviceWithOtp(data.email, data.otp, deviceRowId);



         res.status(200).json({

            message: 'Device removed successfully. Sessions on this device have been signed out.',

         });

      } catch (error) {

         handleAuthControllerError(res, error, 'Failed to remove device');

      }

   };



   private parseRequestRemovalOtpBody(body: unknown): RequestDeviceRemovalOtpRequest {

      if (!body || typeof body !== 'object' || Array.isArray(body)) {

         throw new ValidationError('Invalid request body', {}, 400, 'VALIDATION_ERROR');

      }



      const record = body as Record<string, unknown>;

      const email = typeof record['email'] === 'string' ? record['email'].trim().toLowerCase() : '';

      const deviceId = typeof record['deviceId'] === 'string' ? record['deviceId'].trim() : '';



      if (!email || !deviceId) {

         throw new ValidationError(

            'email and deviceId are required',

            {},

            400,

            'VALIDATION_ERROR',

         );

      }



      return { email, deviceId };

   }



   private parseRemoveDeviceWithOtpBody(body: unknown): RemoveDeviceWithOtpRequest {

      if (!body || typeof body !== 'object' || Array.isArray(body)) {

         throw new ValidationError('Invalid request body', {}, 400, 'VALIDATION_ERROR');

      }



      const record = body as Record<string, unknown>;

      const email = typeof record['email'] === 'string' ? record['email'].trim().toLowerCase() : '';

      const otp = typeof record['otp'] === 'string' ? record['otp'].trim() : '';



      if (!email || !otp) {

         throw new ValidationError('email and otp are required', {}, 400, 'VALIDATION_ERROR');

      }



      return { email, otp };

   }

}



export const userDeviceController = new UserDeviceController();


