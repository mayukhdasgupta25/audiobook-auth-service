const mockPublish = jest.fn().mockResolvedValue(1);
const mockCreateSubscriberClient = jest.fn();

jest.mock('../../src/services/redis', () => ({
   redisService: {
      publish: mockPublish,
      createSubscriberClient: mockCreateSubscriberClient,
   },
}));

jest.mock('../../src/utils/logger', () => ({
   sseLogger: { info: jest.fn(), error: jest.fn() },
}));

import { DomainEventPublisher } from '../../src/services/DomainEventPublisher';
import { AUTH_SSE_REDIS_CHANNEL } from '../../src/types/domainCacheEvents';
import { buildCacheInvalidationEvent } from '../../src/constants/cacheQueryKeys';
import { sseLogger } from '../../src/utils/logger';

describe('DomainEventPublisher', () => {
   beforeEach(() => {
      mockPublish.mockClear();
   });

   it('publish serializes payload and calls Redis PUBLISH on the auth channel', async () => {
      const publisher = DomainEventPublisher.getInstance();
      const event = buildCacheInvalidationEvent('organization', 'updated', 'org-1', {
         organizationId: 'org-1',
      });

      await publisher.publish(event);

      expect(mockPublish).toHaveBeenCalledWith(
         AUTH_SSE_REDIS_CHANNEL,
         JSON.stringify(event),
      );
   });

   it('logs errors without throwing when publish fails', async () => {
      mockPublish.mockRejectedValueOnce(new Error('redis down'));
      const publisher = DomainEventPublisher.getInstance();
      const event = buildCacheInvalidationEvent('user', 'created', 'user-1');

      await expect(publisher.publish(event)).resolves.toBeUndefined();
      expect(sseLogger.error).toHaveBeenCalled();
   });

   it('exposes the static channel name', () => {
      expect(DomainEventPublisher.channel()).toBe(AUTH_SSE_REDIS_CHANNEL);
   });
});
