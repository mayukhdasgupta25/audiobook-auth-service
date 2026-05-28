import { PrismaClient } from '@prisma/client';
import { UserDeviceService } from './UserDeviceService';

const prisma = new PrismaClient();
export const userDeviceService = new UserDeviceService(prisma);
