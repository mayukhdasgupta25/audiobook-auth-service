import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { authenticateToken, requireAdmin } from '../middleware';
import { UserSubscriptionController } from '../controllers/UserSubscriptionController';
import {
   validatePagination,
   validateCuidParam,
   validateCreateSubscription,
   validateUpdateSubscription,
   validateCancelBody,
   validateChangePlan,
   validateUserIdParam,
} from '../middleware/subscriptionValidation';

const prisma = new PrismaClient();
const controller = new UserSubscriptionController(prisma);
const router = Router();

router.use(authenticateToken);
router.get('/me', controller.getMySubscription);
router.get('/me/history', validatePagination, controller.getMySubscriptionHistory);
router.get('/me/tier', controller.getMyTier);
router.get('/user/:userId', validateUserIdParam, validatePagination, controller.getSubscriptionsByUser);
router.get('/', requireAdmin, validatePagination, controller.getAllSubscriptions);
router.post('/', validateCreateSubscription, controller.createSubscription);
router.post('/:id/cancel', validateCuidParam('id'), validateCancelBody, controller.cancelSubscription);
router.post('/:id/renew', validateCuidParam('id'), controller.renewSubscription);
router.post('/:id/change-plan', validateCuidParam('id'), validateChangePlan, controller.changeSubscriptionPlan);
router.delete('/:id/pending-change', validateCuidParam('id'), controller.cancelPendingPlanChange);
router.get('/:id', validateCuidParam('id'), controller.getSubscriptionById);
router.put('/:id', validateCuidParam('id'), validateUpdateSubscription, controller.updateSubscription);
router.delete('/:id', requireAdmin, validateCuidParam('id'), controller.deleteSubscription);

export default router;
