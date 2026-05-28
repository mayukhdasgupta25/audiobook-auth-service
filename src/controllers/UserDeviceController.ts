import { Request, Response } from 'express';
import { userDeviceService } from '../services/userDevice';
import { AuthError, AuthenticatedRequest } from '../types';
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

   removeDevice = async (req: Request, res: Response): Promise<void> => {
      try {
         const userId = this.getAuthUserId(req);

         const deviceId = req.params['id'];
         if (!deviceId || typeof deviceId !== 'string') {
            throw new AuthError('Device id is required', 400, 'VALIDATION_ERROR');
         }

         await userDeviceService.removeDevice(userId, deviceId);

         res.status(200).json({
            message: 'Device removed successfully. Sessions on this device have been signed out.',
         });
      } catch (error) {
         handleAuthControllerError(res, error, 'Failed to remove device');
      }
   };
}

export const userDeviceController = new UserDeviceController();
