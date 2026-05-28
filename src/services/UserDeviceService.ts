import {
   PrismaClient,
   Role,
   UserDevice,
   UserDeviceChangeType,
   SubscriptionStatus,
} from '@prisma/client';
import { AuthError } from '../types';
import type { DeviceContext, DeviceRequestMeta } from '../types';
import { getCalendarMonthBounds, parsePlanFeatures, resolveMaxDevices } from '../utils/deviceLimits';

export interface UserDeviceDto {
   id: string;
   deviceId: string;
   deviceName: string | null;
   platform: string | null;
   lastSeenAt: Date;
   createdAt: Date;
}

export interface DeviceLimitInfo {
   maxDevices: number;
   registeredCount: number;
   remainingDeviceChanges: number;
}

function toUserDeviceDto(device: UserDevice): UserDeviceDto {
   return {
      id: device.id,
      deviceId: device.deviceId,
      deviceName: device.deviceName,
      platform: device.platform,
      lastSeenAt: device.lastSeenAt,
      createdAt: device.createdAt,
   };
}

export class UserDeviceService {
   constructor(private prisma: PrismaClient) {}

   async getMaxDevicesForUser(userId: string): Promise<number> {
      const features = await this.getPlanFeaturesForUser(userId);
      return resolveMaxDevices(features);
   }

   async getDeviceLimitInfo(userId: string): Promise<DeviceLimitInfo> {
      const [maxDevices, registeredCount, remainingDeviceChanges] = await Promise.all([
         this.getMaxDevicesForUser(userId),
         this.countDevices(userId),
         this.getRemainingDeviceChanges(userId),
      ]);
      return { maxDevices, registeredCount, remainingDeviceChanges };
   }

   async countDevices(userId: string): Promise<number> {
      return this.prisma.userDevice.count({ where: { userId } });
   }

   async listDevices(userId: string): Promise<UserDeviceDto[]> {
      const devices = await this.prisma.userDevice.findMany({
         where: { userId },
         orderBy: { lastSeenAt: 'desc' },
      });
      return devices.map(toUserDeviceDto);
   }

   /**
    * Register or touch a device during auth. Skipped for ADMIN users (returns null).
    */
   async resolveDeviceForAuth(
      userId: string,
      role: Role,
      device: DeviceContext,
      meta?: DeviceRequestMeta,
   ): Promise<UserDevice | null> {
      if (role === Role.ADMIN) {
         return null;
      }

      const maxDevices = await this.getMaxDevicesForUser(userId);
      const existing = await this.prisma.userDevice.findUnique({
         where: { userId_deviceId: { userId, deviceId: device.deviceId } },
      });

      if (existing) {
         return this.prisma.userDevice.update({
            where: { id: existing.id },
            data: {
               lastSeenAt: new Date(),
               ...(device.deviceName !== undefined ? { deviceName: device.deviceName } : {}),
               ...(device.platform !== undefined ? { platform: device.platform } : {}),
               ...(meta?.userAgent !== undefined ? { userAgent: meta.userAgent } : {}),
               ...(meta?.ipAddress !== undefined ? { ipAddress: meta.ipAddress } : {}),
            },
         });
      }

      const currentCount = await this.countDevices(userId);
      if (currentCount >= maxDevices) {
         const registeredDevices = await this.listDevices(userId);
         throw new AuthError(
            'Device limit reached for your subscription plan',
            403,
            'DEVICE_LIMIT_EXCEEDED',
            { maxDevices, registeredDevices },
         );
      }

      return this.prisma.userDevice.create({
         data: {
            userId,
            deviceId: device.deviceId,
            deviceName: device.deviceName ?? null,
            platform: device.platform ?? null,
            userAgent: meta?.userAgent ?? null,
            ipAddress: meta?.ipAddress ?? null,
         },
      });
   }

   async assertDeviceExistsForRefresh(userDeviceId: string | null): Promise<void> {
      if (!userDeviceId) {
         return;
      }

      const device = await this.prisma.userDevice.findUnique({
         where: { id: userDeviceId },
      });

      if (!device) {
         throw new AuthError(
            'Device is no longer registered. Please sign in again.',
            403,
            'DEVICE_NOT_REGISTERED',
         );
      }

      await this.prisma.userDevice.update({
         where: { id: userDeviceId },
         data: { lastSeenAt: new Date() },
      });
   }

   async removeDevice(userId: string, deviceRowId: string): Promise<void> {
      const device = await this.prisma.userDevice.findFirst({
         where: { id: deviceRowId, userId },
      });

      if (!device) {
         throw new AuthError('Device not found', 404, 'DEVICE_NOT_FOUND');
      }

      const deviceChangesPerMonth = await this.getDeviceChangesPerMonthForUser(userId);

      if (deviceChangesPerMonth === 0) {
         throw new AuthError(
            'Your plan does not allow removing devices',
            403,
            'DEVICE_CHANGES_NOT_ALLOWED',
         );
      }

      const remaining = await this.getRemainingDeviceChanges(userId);
      if (remaining <= 0) {
         throw new AuthError(
            'Monthly device change limit reached',
            403,
            'DEVICE_CHANGE_QUOTA_EXCEEDED',
         );
      }

      await this.prisma.$transaction(async (tx) => {
         await tx.refreshToken.updateMany({
            where: { userDeviceId: device.id, isRevoked: false },
            data: { isRevoked: true },
         });

         await tx.userDeviceChange.create({
            data: {
               userId,
               type: UserDeviceChangeType.REMOVED,
               userDeviceId: device.id,
            },
         });

         await tx.userDevice.delete({ where: { id: device.id } });
      });
   }

   async revokeRefreshTokensForDevice(userDeviceId: string): Promise<void> {
      await this.prisma.refreshToken.updateMany({
         where: { userDeviceId, isRevoked: false },
         data: { isRevoked: true },
      });
   }

   async getRemainingDeviceChanges(userId: string): Promise<number> {
      const allowance = await this.getDeviceChangesPerMonthForUser(userId);
      const used = await this.countDeviceChangesThisMonth(userId);
      return Math.max(0, allowance - used);
   }

   private async countDeviceChangesThisMonth(userId: string): Promise<number> {
      const { start, end } = getCalendarMonthBounds();
      return this.prisma.userDeviceChange.count({
         where: {
            userId,
            createdAt: { gte: start, lt: end },
         },
      });
   }

   private async getDeviceChangesPerMonthForUser(userId: string): Promise<number> {
      const features = await this.getPlanFeaturesForUser(userId);
      if (!features) {
         return 0;
      }
      return features.deviceChangesPerMonth;
   }

   private async getPlanFeaturesForUser(userId: string) {
      const sub = await this.prisma.userSubscription.findFirst({
         where: {
            userId,
            status: {
               in: [
                  SubscriptionStatus.ACTIVE,
                  SubscriptionStatus.TRIALING,
                  SubscriptionStatus.PAST_DUE,
               ],
            },
         },
         orderBy: { createdAt: 'desc' },
         include: { plan: true },
      });

      if (!sub?.plan.features) {
         return null;
      }

      const features = parsePlanFeatures(sub.plan.features);
      if (!features) {
         console.warn(
            `User ${userId} has subscription plan ${sub.plan.id} with invalid features JSON; using free-tier device defaults`,
         );
         return null;
      }

      return features;
   }
}
