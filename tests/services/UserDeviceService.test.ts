jest.mock('../../src/services/otp', () => ({
   otpService: {
      createOTP: jest.fn(),
      verifyOTP: jest.fn(),
      getResendCooldownState: jest.fn(),
   },
}));

import { OtpPurpose, Role, UserDeviceChangeType } from '@prisma/client';
import { UserDeviceService } from '../../src/services/UserDeviceService';
import { AuthError } from '../../src/types';
import { otpService } from '../../src/services/otp';

const standardFeatures = {
   audiobookCatalog: 'curated_wide' as const,
   maxDevices: 2,
   audioQuality: 'high' as const,
   deviceChangesPerMonth: 1,
};

const premiumFeatures = {
   audiobookCatalog: 'all' as const,
   maxDevices: 3,
   audioQuality: 'best' as const,
   deviceChangesPerMonth: 3,
};

const mockPrisma = {
   user: {
      findUnique: jest.fn(),
   },
   userDevice: {
      findUnique: jest.fn(),
      findFirst: jest.fn(),
      findMany: jest.fn(),
      count: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
   },
   userSubscription: {
      findFirst: jest.fn(),
   },
   userDeviceChange: {
      count: jest.fn(),
      create: jest.fn(),
   },
   refreshToken: {
      updateMany: jest.fn(),
   },
   $transaction: jest.fn((fn: (tx: typeof mockPrisma) => Promise<unknown>) => fn(mockPrisma)),
} as any;

describe('UserDeviceService', () => {
   let service: UserDeviceService;

   beforeEach(() => {
      service = new UserDeviceService(mockPrisma);
      jest.clearAllMocks();
      mockPrisma.userSubscription.findFirst.mockResolvedValue(null);
   });

   describe('getMaxDevicesForUser', () => {
      it('returns 1 when user has no active subscription', async () => {
         await expect(service.getMaxDevicesForUser('user-1')).resolves.toBe(1);
      });

      it('returns plan maxDevices capped at platform max', async () => {
         mockPrisma.userSubscription.findFirst.mockResolvedValue({
            plan: { id: 'plan', features: standardFeatures },
         });
         await expect(service.getMaxDevicesForUser('user-1')).resolves.toBe(2);
      });
   });

   describe('getDeviceLimitInfo', () => {
      it('returns non-restrictive limits for non-LISTENER roles', async () => {
         mockPrisma.userDevice.count.mockResolvedValue(2);

         await expect(service.getDeviceLimitInfo('user-1', Role.AUTHOR)).resolves.toEqual({
            maxDevices: 3,
            registeredCount: 2,
            remainingDeviceChanges: 3,
         });
      });
   });

   describe('resolveDeviceForAuth', () => {
      const device = { deviceId: 'client-device-1' };

      it('skips enforcement for GLOBAL_ADMIN', async () => {
         await expect(
            service.resolveDeviceForAuth('admin-1', Role.GLOBAL_ADMIN, device),
         ).resolves.toBeNull();
         expect(mockPrisma.userDevice.findUnique).not.toHaveBeenCalled();
      });

      it('updates lastSeenAt for known device', async () => {
         const existing = {
            id: 'row-1',
            userId: 'user-1',
            deviceId: 'client-device-1',
            deviceName: null,
            platform: null,
            lastSeenAt: new Date('2020-01-01'),
            createdAt: new Date('2020-01-01'),
         };
         mockPrisma.userDevice.findUnique.mockResolvedValue(existing);
         mockPrisma.userDevice.update.mockResolvedValue({ ...existing, lastSeenAt: new Date() });

         await service.resolveDeviceForAuth('user-1', Role.LISTENER, device);
         expect(mockPrisma.userDevice.update).toHaveBeenCalled();
         expect(mockPrisma.userDevice.create).not.toHaveBeenCalled();
      });

      it('blocks second device when no subscription (max 1)', async () => {
         mockPrisma.userDevice.findUnique.mockResolvedValue(null);
         mockPrisma.userDevice.count.mockResolvedValue(1);
         mockPrisma.userDevice.findMany.mockResolvedValue([
            {
               id: 'row-1',
               deviceId: 'existing',
               deviceName: null,
               platform: null,
               lastSeenAt: new Date(),
               createdAt: new Date(),
            },
         ]);

         await expect(
            service.resolveDeviceForAuth('user-1', Role.LISTENER, { deviceId: 'new-device' }),
         ).rejects.toMatchObject({
            code: 'DEVICE_LIMIT_EXCEEDED',
            statusCode: 403,
         });
      });

      it('allows new device under plan limit', async () => {
         mockPrisma.userSubscription.findFirst.mockResolvedValue({
            plan: { id: 'plan', features: standardFeatures },
         });
         mockPrisma.userDevice.findUnique.mockResolvedValue(null);
         mockPrisma.userDevice.count.mockResolvedValue(1);
         mockPrisma.userDevice.create.mockResolvedValue({
            id: 'row-2',
            userId: 'user-1',
            deviceId: 'new-device',
            deviceName: null,
            platform: null,
            lastSeenAt: new Date(),
            createdAt: new Date(),
         });

         await service.resolveDeviceForAuth('user-1', Role.LISTENER, { deviceId: 'new-device' });
         expect(mockPrisma.userDevice.create).toHaveBeenCalled();
      });

      it('blocks third device on Standard plan (max 2)', async () => {
         mockPrisma.userSubscription.findFirst.mockResolvedValue({
            plan: { id: 'plan', features: standardFeatures },
         });
         mockPrisma.userDevice.findUnique.mockResolvedValue(null);
         mockPrisma.userDevice.count.mockResolvedValue(2);
         mockPrisma.userDevice.findMany.mockResolvedValue([
            { id: 'a', deviceId: 'd1', deviceName: null, platform: null, lastSeenAt: new Date(), createdAt: new Date() },
            { id: 'b', deviceId: 'd2', deviceName: null, platform: null, lastSeenAt: new Date(), createdAt: new Date() },
         ]);

         await expect(
            service.resolveDeviceForAuth('user-1', Role.LISTENER, { deviceId: 'd3' }),
         ).rejects.toBeInstanceOf(AuthError);
      });

      it('allows AUTHOR to register beyond plan max device count', async () => {
         mockPrisma.userSubscription.findFirst.mockResolvedValue({
            plan: { id: 'plan', features: standardFeatures },
         });
         mockPrisma.userDevice.findUnique.mockResolvedValue(null);
         mockPrisma.userDevice.count.mockResolvedValue(2);
         mockPrisma.userDevice.create.mockResolvedValue({
            id: 'row-3',
            userId: 'user-1',
            deviceId: 'd3',
            deviceName: null,
            platform: null,
            lastSeenAt: new Date(),
            createdAt: new Date(),
         });

         await service.resolveDeviceForAuth('user-1', Role.AUTHOR, { deviceId: 'd3' });
         expect(mockPrisma.userDevice.create).toHaveBeenCalled();
      });

      it('allows ORG_ADMIN to register beyond plan max device count', async () => {
         mockPrisma.userSubscription.findFirst.mockResolvedValue({
            plan: { id: 'plan', features: standardFeatures },
         });
         mockPrisma.userDevice.findUnique.mockResolvedValue(null);
         mockPrisma.userDevice.count.mockResolvedValue(2);
         mockPrisma.userDevice.create.mockResolvedValue({
            id: 'row-3',
            userId: 'user-1',
            deviceId: 'd3',
            deviceName: null,
            platform: null,
            lastSeenAt: new Date(),
            createdAt: new Date(),
         });

         await service.resolveDeviceForAuth('user-1', Role.ORG_ADMIN, { deviceId: 'd3' });
         expect(mockPrisma.userDevice.create).toHaveBeenCalled();
      });
   });

   describe('removeDevice', () => {
      it('allows one remove per month when user has no subscription', async () => {
         mockPrisma.userDevice.findFirst.mockResolvedValue({
            id: 'dev-1',
            userId: 'user-1',
            deviceId: 'client-1',
         });
         mockPrisma.userDeviceChange.count.mockResolvedValue(0);

         await service.removeDevice('user-1', 'dev-1', Role.LISTENER);

         expect(mockPrisma.userDevice.delete).toHaveBeenCalledWith({ where: { id: 'dev-1' } });
      });

      it('rejects remove when subscribed plan has zero device changes', async () => {
         mockPrisma.userSubscription.findFirst.mockResolvedValue({
            plan: {
               id: 'plan',
               features: {
                  audiobookCatalog: 'selected',
                  maxDevices: 1,
                  audioQuality: 'base',
                  deviceChangesPerMonth: 0,
               },
            },
         });
         mockPrisma.userDevice.findFirst.mockResolvedValue({
            id: 'dev-1',
            userId: 'user-1',
            deviceId: 'client-1',
         });

         await expect(service.removeDevice('user-1', 'dev-1', Role.LISTENER)).rejects.toMatchObject({
            code: 'DEVICE_CHANGES_NOT_ALLOWED',
         });
      });

      it('revokes refresh tokens and deletes device on successful remove', async () => {
         mockPrisma.userSubscription.findFirst.mockResolvedValue({
            plan: { id: 'plan', features: premiumFeatures },
         });
         mockPrisma.userDevice.findFirst.mockResolvedValue({
            id: 'dev-1',
            userId: 'user-1',
            deviceId: 'client-1',
         });
         mockPrisma.userDeviceChange.count.mockResolvedValue(0);

         await service.removeDevice('user-1', 'dev-1', Role.LISTENER);

         expect(mockPrisma.refreshToken.updateMany).toHaveBeenCalledWith({
            where: { userDeviceId: 'dev-1', isRevoked: false },
            data: { isRevoked: true },
         });
         expect(mockPrisma.userDeviceChange.create).toHaveBeenCalledWith({
            data: {
               userId: 'user-1',
               type: UserDeviceChangeType.REMOVED,
               userDeviceId: 'dev-1',
            },
         });
         expect(mockPrisma.userDevice.delete).toHaveBeenCalledWith({ where: { id: 'dev-1' } });
      });

      it('rejects remove when monthly quota exhausted', async () => {
         mockPrisma.userSubscription.findFirst.mockResolvedValue({
            plan: { id: 'plan', features: standardFeatures },
         });
         mockPrisma.userDevice.findFirst.mockResolvedValue({
            id: 'dev-1',
            userId: 'user-1',
         });
         mockPrisma.userDeviceChange.count.mockResolvedValue(1);

         await expect(service.removeDevice('user-1', 'dev-1', Role.LISTENER)).rejects.toMatchObject({
            code: 'DEVICE_CHANGE_QUOTA_EXCEEDED',
         });
      });

      it('allows AUTHOR to remove device when monthly quota exhausted', async () => {
         mockPrisma.userSubscription.findFirst.mockResolvedValue({
            plan: { id: 'plan', features: standardFeatures },
         });
         mockPrisma.userDevice.findFirst.mockResolvedValue({
            id: 'dev-1',
            userId: 'user-1',
            deviceId: 'client-1',
         });
         mockPrisma.userDeviceChange.count.mockResolvedValue(1);

         await service.removeDevice('user-1', 'dev-1', Role.AUTHOR);

         expect(mockPrisma.userDevice.delete).toHaveBeenCalledWith({ where: { id: 'dev-1' } });
      });
   });

   describe('requestDeviceRemovalOtp', () => {
      it('does not send OTP when user is not found', async () => {
         mockPrisma.user.findUnique.mockResolvedValue(null);

         await service.requestDeviceRemovalOtp('missing@example.com', 'dev-1');

         expect(otpService.createOTP).not.toHaveBeenCalled();
      });

      it('does not send OTP when device is not owned by user', async () => {
         mockPrisma.user.findUnique.mockResolvedValue({
            id: 'user-1',
            email: 'user@example.com',
            role: Role.LISTENER,
         });
         mockPrisma.userDevice.findFirst.mockResolvedValue(null);

         await service.requestDeviceRemovalOtp('user@example.com', 'dev-1');

         expect(otpService.createOTP).not.toHaveBeenCalled();
      });

      it('sends OTP when user, device, and quota checks pass', async () => {
         mockPrisma.user.findUnique.mockResolvedValue({
            id: 'user-1',
            email: 'user@example.com',
            role: Role.LISTENER,
         });
         mockPrisma.userDevice.findFirst.mockResolvedValue({ id: 'dev-1', userId: 'user-1' });
         mockPrisma.userSubscription.findFirst.mockResolvedValue({
            plan: { id: 'plan', features: premiumFeatures },
         });
         mockPrisma.userDeviceChange.count.mockResolvedValue(0);

         await service.requestDeviceRemovalOtp('user@example.com', 'dev-1');

         expect(otpService.createOTP).toHaveBeenCalledWith(
            'user-1',
            OtpPurpose.DEVICE_REMOVAL,
            'user@example.com',
         );
      });
   });

   describe('resendDeviceRemovalOtp', () => {
      it('rejects when no active OTP exists', async () => {
         mockPrisma.user.findUnique.mockResolvedValue({
            id: 'user-1',
            email: 'user@example.com',
            role: Role.LISTENER,
         });
         mockPrisma.userDevice.findFirst.mockResolvedValue({ id: 'dev-1', userId: 'user-1' });
         mockPrisma.userDeviceChange.count.mockResolvedValue(0);
         (otpService.getResendCooldownState as jest.Mock).mockResolvedValue({
            hasActiveOtp: false,
            remainingSeconds: 0,
         });

         await expect(
            service.resendDeviceRemovalOtp('user@example.com', 'dev-1'),
         ).rejects.toMatchObject({ code: 'DEVICE_REMOVAL_OTP_NOT_FOUND' });
      });

      it('rejects when 30s cooldown has not elapsed', async () => {
         mockPrisma.user.findUnique.mockResolvedValue({
            id: 'user-1',
            email: 'user@example.com',
            role: Role.LISTENER,
         });
         mockPrisma.userDevice.findFirst.mockResolvedValue({ id: 'dev-1', userId: 'user-1' });
         mockPrisma.userDeviceChange.count.mockResolvedValue(0);
         (otpService.getResendCooldownState as jest.Mock).mockResolvedValue({
            hasActiveOtp: true,
            remainingSeconds: 12,
         });

         await expect(
            service.resendDeviceRemovalOtp('user@example.com', 'dev-1'),
         ).rejects.toMatchObject({
            code: 'OTP_RESEND_COOLDOWN',
            statusCode: 429,
            details: { remainingSeconds: 12 },
         });
      });

      it('sends new OTP when cooldown has elapsed', async () => {
         mockPrisma.user.findUnique.mockResolvedValue({
            id: 'user-1',
            email: 'user@example.com',
            role: Role.LISTENER,
         });
         mockPrisma.userDevice.findFirst.mockResolvedValue({ id: 'dev-1', userId: 'user-1' });
         mockPrisma.userDeviceChange.count.mockResolvedValue(0);
         (otpService.getResendCooldownState as jest.Mock).mockResolvedValue({
            hasActiveOtp: true,
            remainingSeconds: 0,
         });

         await service.resendDeviceRemovalOtp('user@example.com', 'dev-1');

         expect(otpService.createOTP).toHaveBeenCalledWith(
            'user-1',
            OtpPurpose.DEVICE_REMOVAL,
            'user@example.com',
         );
      });
   });

   describe('removeDeviceWithOtp', () => {
      it('throws INVALID_OTP when verification fails', async () => {
         mockPrisma.user.findUnique.mockResolvedValue({
            id: 'user-1',
            email: 'user@example.com',
            role: Role.LISTENER,
         });
         (otpService.verifyOTP as jest.Mock).mockRejectedValue(new Error('Invalid OTP'));

         await expect(
            service.removeDeviceWithOtp('user@example.com', '000000', 'dev-1'),
         ).rejects.toMatchObject({ code: 'INVALID_OTP', statusCode: 400 });
      });

      it('removes device after successful OTP verification', async () => {
         mockPrisma.user.findUnique.mockResolvedValue({
            id: 'user-1',
            email: 'user@example.com',
            role: Role.LISTENER,
         });
         (otpService.verifyOTP as jest.Mock).mockResolvedValue(true);
         mockPrisma.userSubscription.findFirst.mockResolvedValue({
            plan: { id: 'plan', features: premiumFeatures },
         });
         mockPrisma.userDevice.findFirst.mockResolvedValue({
            id: 'dev-1',
            userId: 'user-1',
         });
         mockPrisma.userDeviceChange.count.mockResolvedValue(0);

         await service.removeDeviceWithOtp('user@example.com', '123456', 'dev-1');

         expect(otpService.verifyOTP).toHaveBeenCalledWith(
            'user-1',
            '123456',
            OtpPurpose.DEVICE_REMOVAL,
         );
         expect(mockPrisma.userDevice.delete).toHaveBeenCalledWith({ where: { id: 'dev-1' } });
      });
   });

   describe('assertDeviceExistsForRefresh', () => {
      it('no-ops when userDeviceId is null', async () => {
         await expect(service.assertDeviceExistsForRefresh(null)).resolves.toBeUndefined();
      });

      it('throws when device row was deleted', async () => {
         mockPrisma.userDevice.findUnique.mockResolvedValue(null);
         await expect(service.assertDeviceExistsForRefresh('dev-1')).rejects.toMatchObject({
            code: 'DEVICE_NOT_REGISTERED',
         });
      });
   });
});
