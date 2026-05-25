import { SubscriptionPlan as PrismaSubscriptionPlan, BillingInterval } from '@prisma/client';
import { formatSubscriptionPlanFeatures } from '../utils/formatSubscriptionPlanFeatures';

export interface SubscriptionPlanDto {
   id: string;
   name: string;
   description: string | null;
   price: number;
   currency: string;
   tierLevel: number;
   billingInterval: BillingInterval;
   trialDays: number;
   /** Raw feature flags stored in the database */
   features: unknown;
   /** Human-readable feature lines for clients (from config/subscription-plan-features.en.yml) */
   featureDescriptions: string[];
   isActive: boolean;
   createdAt: Date;
   updatedAt: Date;
}

export interface CreateSubscriptionPlanDto {
   name: string;
   description?: string;
   price: number;
   currency?: string;
   tierLevel?: number;
   billingInterval?: BillingInterval;
   trialDays?: number;
   features?: unknown;
   isActive?: boolean;
}

export interface UpdateSubscriptionPlanDto {
   name?: string;
   description?: string | null;
   price?: number;
   currency?: string;
   tierLevel?: number;
   billingInterval?: BillingInterval;
   trialDays?: number;
   features?: unknown;
   isActive?: boolean;
}

export interface SubscriptionPlanQueryParams {
   page?: number;
   limit?: number;
   sortBy?: string;
   sortOrder?: 'asc' | 'desc';
   isActive?: boolean;
   billingInterval?: BillingInterval;
   search?: string;
}

export function toSubscriptionPlanDto(plan: PrismaSubscriptionPlan): SubscriptionPlanDto {
   const features = plan.features ?? null;
   return {
      id: plan.id,
      name: plan.name,
      description: plan.description ?? null,
      price: typeof plan.price === 'number' ? plan.price : Number(plan.price.toString()),
      currency: plan.currency,
      tierLevel: plan.tierLevel,
      billingInterval: plan.billingInterval,
      trialDays: plan.trialDays,
      features,
      featureDescriptions: formatSubscriptionPlanFeatures(features),
      isActive: plan.isActive,
      createdAt: plan.createdAt,
      updatedAt: plan.updatedAt,
   };
}
