import {
   UserSubscription as PrismaUserSubscription,
   SubscriptionStatus,
   PlanChangeType,
} from '@prisma/client';
import { SubscriptionPlanDto, toSubscriptionPlanDto } from './SubscriptionPlanDto';

export interface UserSubscriptionDto {
   id: string;
   userId: string;
   planId: string;
   status: SubscriptionStatus;
   startDate: Date;
   endDate: Date | null;
   currentPeriodStart: Date;
   currentPeriodEnd: Date;
   trialEndsAt: Date | null;
   cancelAtPeriodEnd: boolean;
   canceledAt: Date | null;
   autoRenew: boolean;
   paymentMethod: string | null;
   pendingPlanId: string | null;
   pendingPlanChangeAt: Date | null;
   pendingPlanChangeType: PlanChangeType | null;
   createdAt: Date;
   updatedAt: Date;
}

export interface UserSubscriptionWithPlan extends UserSubscriptionDto {
   plan: SubscriptionPlanDto;
   pendingPlan?: SubscriptionPlanDto | null;
}

export interface CreateUserSubscriptionDto {
   userId: string;
   planId: string;
   autoRenew?: boolean;
   paymentMethod?: string;
   startDate?: Date | string;
   startTrial?: boolean;
}

export interface UpdateUserSubscriptionDto {
   autoRenew?: boolean;
   paymentMethod?: string | null;
   cancelAtPeriodEnd?: boolean;
   status?: SubscriptionStatus;
}

export interface CancelSubscriptionDto {
   cancelAtPeriodEnd?: boolean;
}

export interface ChangeSubscriptionPlanDto {
   planId: string;
}

export interface ChangePlanResult {
   changeType: PlanChangeType;
   effectiveAt: Date;
   prorationAmount: number | null;
   subscription: UserSubscriptionWithPlan;
}

export interface UserSubscriptionQueryParams {
   page?: number;
   limit?: number;
   sortBy?: string;
   sortOrder?: 'asc' | 'desc';
   userId?: string;
   planId?: string;
   status?: SubscriptionStatus;
}

type SubscriptionWithPlanRelations = PrismaUserSubscription & {
   plan: Parameters<typeof toSubscriptionPlanDto>[0];
   pendingPlan?: Parameters<typeof toSubscriptionPlanDto>[0] | null;
};

export function toUserSubscriptionDto(sub: PrismaUserSubscription): UserSubscriptionDto {
   return {
      id: sub.id,
      userId: sub.userId,
      planId: sub.planId,
      status: sub.status,
      startDate: sub.startDate,
      endDate: sub.endDate ?? null,
      currentPeriodStart: sub.currentPeriodStart,
      currentPeriodEnd: sub.currentPeriodEnd,
      trialEndsAt: sub.trialEndsAt ?? null,
      cancelAtPeriodEnd: sub.cancelAtPeriodEnd,
      canceledAt: sub.canceledAt ?? null,
      autoRenew: sub.autoRenew,
      paymentMethod: sub.paymentMethod ?? null,
      pendingPlanId: sub.pendingPlanId ?? null,
      pendingPlanChangeAt: sub.pendingPlanChangeAt ?? null,
      pendingPlanChangeType: sub.pendingPlanChangeType ?? null,
      createdAt: sub.createdAt,
      updatedAt: sub.updatedAt,
   };
}

export function toUserSubscriptionWithPlan(sub: SubscriptionWithPlanRelations): UserSubscriptionWithPlan {
   const dto: UserSubscriptionWithPlan = {
      ...toUserSubscriptionDto(sub),
      plan: toSubscriptionPlanDto(sub.plan),
   };
   if (sub.pendingPlan) {
      dto.pendingPlan = toSubscriptionPlanDto(sub.pendingPlan);
   } else {
      dto.pendingPlan = null;
   }
   return dto;
}

export const subscriptionInclude = {
   plan: true,
   pendingPlan: true,
} as const;
