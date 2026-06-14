import { Request, Response } from 'express';
import { authService } from '../services/auth';
import { userProfileService } from '../services/userProfile';
import { UpdateUserProfileRequest } from '../types';

export class UserProfileController {
   async updateProfile(req: Request, res: Response): Promise<void> {
      try {
         const userId = (req as Request & { user: { id: string } }).user.id;
         const updated = await userProfileService.updateUserProfile(
            userId,
            req.body as UpdateUserProfileRequest,
         );

         res.json({
            message: 'Profile updated successfully',
            user: updated,
         });
      } catch (error) {
         res.status(500).json({
            error: error instanceof Error ? error.message : 'Failed to update profile',
         });
      }
   }

   async getProfile(req: Request, res: Response): Promise<void> {
      try {
         const userId = (req as Request & { user: { id: string } }).user.id;
         const user = await authService.getUserById(userId);

         if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
         }

         res.json({ user });
      } catch (error) {
         res.status(500).json({
            error: error instanceof Error ? error.message : 'Failed to get profile',
         });
      }
   }
}

export const userProfileController = new UserProfileController();
