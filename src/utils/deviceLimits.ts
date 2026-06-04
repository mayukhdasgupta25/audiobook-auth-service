import {
   isSubscriptionPlanFeatures,
   SubscriptionPlanFeatures,
} from '../types/subscriptionPlanFeatures';

export const PLATFORM_MAX_DEVICES = 3;
export const FREE_TIER_MAX_DEVICES = 1;
export const FREE_TIER_DEVICE_CHANGES_PER_MONTH = 1;

export function resolveMaxDevices(features: SubscriptionPlanFeatures | null): number {
   if (!features) {
      return FREE_TIER_MAX_DEVICES;
   }
   return Math.min(PLATFORM_MAX_DEVICES, features.maxDevices);
}

export function resolveDeviceChangesPerMonth(features: SubscriptionPlanFeatures | null): number {
   if (!features) {
      return FREE_TIER_DEVICE_CHANGES_PER_MONTH;
   }
   return features.deviceChangesPerMonth;
}

export function parsePlanFeatures(features: unknown): SubscriptionPlanFeatures | null {
   if (!isSubscriptionPlanFeatures(features)) {
      return null;
   }
   return features;
}

export function getCalendarMonthBounds(date: Date = new Date()): { start: Date; end: Date } {
   const start = new Date(date.getFullYear(), date.getMonth(), 1);
   const end = new Date(date.getFullYear(), date.getMonth() + 1, 1);
   return { start, end };
}
