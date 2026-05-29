import { PrismaClient } from '@prisma/client';
import { UserDeviceService, DEVICE_REMOVAL_OTP_GENERIC_MESSAGE } from './UserDeviceService';

const prisma = new PrismaClient();
export const userDeviceService = new UserDeviceService(prisma);
export { DEVICE_REMOVAL_OTP_GENERIC_MESSAGE };
