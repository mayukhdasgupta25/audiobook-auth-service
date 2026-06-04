import { Router } from 'express';
import { userDeviceController } from '../controllers/UserDeviceController';
import { authenticateToken, passwordResetRateLimit } from '../middleware';

const router = Router();

router.get('/', authenticateToken, userDeviceController.listMyDevices.bind(userDeviceController));
router.post(
   '/request-removal-otp',
   passwordResetRateLimit,
   userDeviceController.requestRemovalOtp.bind(userDeviceController),
);
router.post(
   '/resend-removal-otp',
   passwordResetRateLimit,
   userDeviceController.resendRemovalOtp.bind(userDeviceController),
);
router.delete(
   '/:id',
   passwordResetRateLimit,
   userDeviceController.removeDevice.bind(userDeviceController),
);

export default router;
