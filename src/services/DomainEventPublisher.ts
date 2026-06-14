import { buildCacheInvalidationEvent } from '../constants/cacheQueryKeys';
import { AUTH_SSE_REDIS_CHANNEL, CacheInvalidateEvent } from '../types/domainCacheEvents';
import { sseLogger } from '../utils/logger';
import { redisService } from './redis';

export class DomainEventPublisher {
   private static instance: DomainEventPublisher | null = null;

   static getInstance(): DomainEventPublisher {
      if (!DomainEventPublisher.instance) {
         DomainEventPublisher.instance = new DomainEventPublisher();
      }
      return DomainEventPublisher.instance;
   }

   async publish(event: CacheInvalidateEvent): Promise<void> {
      try {
         await redisService.publish(AUTH_SSE_REDIS_CHANNEL, JSON.stringify(event));
         sseLogger.info(
            {
               direction: 'published',
               channel: AUTH_SSE_REDIS_CHANNEL,
               resource: event.resource,
               action: event.action,
               id: event.id,
               queryKeyCount: event.queryKeys.length,
               relatedIds: event.relatedIds,
            },
            'SSE cache-invalidate event published',
         );
      } catch (error) {
         sseLogger.error(
            {
               err: error,
               direction: 'published',
               channel: AUTH_SSE_REDIS_CHANNEL,
               resource: event.resource,
               action: event.action,
               id: event.id,
            },
            'SSE cache-invalidate event publish failed',
         );
      }
   }

   createSubscriber() {
      return redisService.createSubscriberClient();
   }

   static channel(): string {
      return AUTH_SSE_REDIS_CHANNEL;
   }
}

export const domainEventPublisher = DomainEventPublisher.getInstance();

export function emitCacheInvalidation(
   resource: CacheInvalidateEvent['resource'],
   action: CacheInvalidateEvent['action'],
   id: string,
   relatedIds?: CacheInvalidateEvent['relatedIds'],
): void {
   void domainEventPublisher.publish(buildCacheInvalidationEvent(resource, action, id, relatedIds));
}
