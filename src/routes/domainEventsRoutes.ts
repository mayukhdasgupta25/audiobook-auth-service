import { Router } from 'express';
import { domainEventsController } from '../controllers/DomainEventsController';
import { authenticateTokenOrQuery } from '../middleware/authenticateTokenOrQuery';

export function createDomainEventsRoutes(): Router {
   const router = Router();

   router.get('/stream', authenticateTokenOrQuery, domainEventsController.streamCacheEvents);

   return router;
}
