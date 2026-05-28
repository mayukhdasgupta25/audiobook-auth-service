import { Role, UserDeviceChangeType } from '@prisma/client';
import { UserDeviceService } from '../../src/services/UserDeviceService';
import { AuthError } from '../../src/types';

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

   describe('resolveDeviceForAuth', () => {
      const device = { deviceId: 'client-device-1' };

      it('skips enforcement for ADMIN', async () => {
         await expect(
            service.resolveDeviceForAuth('admin-1', Role.ADMIN, device),
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

         await service.resolveDeviceForAuth('user-1', Role.USER, device);
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
            service.resolveDeviceForAuth('user-1', Role.USER, { deviceId: 'new-device' }),
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

         await service.resolveDeviceForAuth('user-1', Role.USER, { deviceId: 'new-device' });
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
            service.resolveDeviceForAuth('user-1', Role.USER, { deviceId: 'd3' }),
         ).rejects.toBeInstanceOf(AuthError);
      });
   });

   describe('removeDevice', () => {
      it('rejects remove when plan has zero device changes', async () => {
         mockPrisma.userDevice.findFirst.mockResolvedValue({
            id: 'dev-1',
            userId: 'user-1',
            deviceId: 'client-1',
         });

         await expect(service.removeDevice('user-1', 'dev-1')).rejects.toMatchObject({
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

         await service.removeDevice('user-1', 'dev-1');

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

         await expect(service.removeDevice('user-1', 'dev-1')).rejects.toMatchObject({
            code: 'DEVICE_CHANGE_QUOTA_EXCEEDED',
         });
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
