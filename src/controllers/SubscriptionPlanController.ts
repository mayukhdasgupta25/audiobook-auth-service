import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { SubscriptionPlanService } from '../services/SubscriptionPlanService';
import {
   CreateSubscriptionPlanDto,
   UpdateSubscriptionPlanDto,
   SubscriptionPlanQueryParams,
} from '../models/SubscriptionPlanDto';
import { subscriptionMessages } from '../utils/subscriptionMessages';
import { handleSubscriptionError, calculatePagination } from '../utils/subscriptionController';

export class SubscriptionPlanController {
   private planService: SubscriptionPlanService;

   constructor(prisma: PrismaClient) {
      this.planService = new SubscriptionPlanService(prisma);
   }

   createPlan = async (req: Request, res: Response): Promise<void> => {
      try {
         const created = await this.planService.createPlan(req.body as CreateSubscriptionPlanDto);
         res.status(201).json({
            message: subscriptionMessages.success.subscription_plans.created,
            plan: created,
         });
      } catch (error) {
         handleSubscriptionError(res, error);
      }
   };

   getAllPlans = async (req: Request, res: Response): Promise<void> => {
      try {
         const queryParams: SubscriptionPlanQueryParams = {
            page: req.query['page'] ? parseInt(req.query['page'] as string, 10) : 1,
            limit: req.query['limit'] ? parseInt(req.query['limit'] as string, 10) : 10,
            sortBy: (req.query['sortBy'] as string) || 'createdAt',
            sortOrder: (req.query['sortOrder'] as 'asc' | 'desc') || 'desc',
         };
         if (req.query['isActive'] !== undefined) queryParams.isActive = req.query['isActive'] === 'true';
         const billingInterval = req.query['billingInterval'] as string | undefined;
         if (billingInterval) queryParams.billingInterval = billingInterval as NonNullable<SubscriptionPlanQueryParams['billingInterval']>;
         if (req.query['search']) queryParams.search = req.query['search'] as string;
         const { plans, totalCount } = await this.planService.getAllPlans(queryParams);
         res.status(200).json({
            message: subscriptionMessages.success.subscription_plans.retrieved,
            plans,
            pagination: calculatePagination(queryParams.page!, queryParams.limit!, totalCount),
         });
      } catch (error) {
         handleSubscriptionError(res, error);
      }
   };

   getPlanById = async (req: Request, res: Response): Promise<void> => {
      try {
         const plan = await this.planService.getPlanById((req.params as { id: string }).id);
         res.status(200).json({
            message: subscriptionMessages.success.subscription_plans.retrieved_by_id,
            plan,
         });
      } catch (error) {
         handleSubscriptionError(res, error);
      }
   };

   updatePlan = async (req: Request, res: Response): Promise<void> => {
      try {
         const updated = await this.planService.updatePlan(
            (req.params as { id: string }).id,
            req.body as UpdateSubscriptionPlanDto
         );
         res.status(200).json({
            message: subscriptionMessages.success.subscription_plans.updated,
            plan: updated,
         });
      } catch (error) {
         handleSubscriptionError(res, error);
      }
   };

   deletePlan = async (req: Request, res: Response): Promise<void> => {
      try {
         const result = await this.planService.deletePlan((req.params as { id: string }).id);
         const message = result.deactivated
            ? subscriptionMessages.success.subscription_plans.deactivated
            : subscriptionMessages.success.subscription_plans.deleted;
         res.status(200).json({ message, ...result });
      } catch (error) {
         handleSubscriptionError(res, error);
      }
   };
}
