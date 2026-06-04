import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { authenticateToken, requireAdmin } from '../middleware';
import { SubscriptionPlanController } from '../controllers/SubscriptionPlanController';
import {
   validatePagination,
   validateCuidParam,
   validateCreatePlan,
   validateUpdatePlan,
} from '../middleware/subscriptionValidation';

const prisma = new PrismaClient();
const controller = new SubscriptionPlanController(prisma);
const router = Router();

router.use(authenticateToken);
router.get('/', validatePagination, controller.getAllPlans);
router.get('/:id', validateCuidParam('id'), controller.getPlanById);
router.post('/', requireAdmin, validateCreatePlan, controller.createPlan);
router.put('/:id', requireAdmin, validateCuidParam('id'), validateUpdatePlan, controller.updatePlan);
router.delete('/:id', requireAdmin, validateCuidParam('id'), controller.deletePlan);

export default router;
