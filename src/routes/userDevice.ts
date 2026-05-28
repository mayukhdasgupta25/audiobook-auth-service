import { Router } from 'express';
import { userDeviceController } from '../controllers/UserDeviceController';
import { authenticateToken } from '../middleware';

const router = Router();

router.get('/', authenticateToken, userDeviceController.listMyDevices.bind(userDeviceController));
router.delete('/:id', authenticateToken, userDeviceController.removeDevice.bind(userDeviceController));

export default router;
