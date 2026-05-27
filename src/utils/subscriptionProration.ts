import { Decimal } from '@prisma/client/runtime/library';
import { SubscriptionStatus } from '@prisma/client';

export interface ProrationInput {
   oldPrice: Decimal | number;
   newPrice: Decimal | number;
   periodStart: Date;
   periodEnd: Date;
   now?: Date;
   status?: SubscriptionStatus;
}

export interface ProrationResult {
   prorationAmount: number;
   remainingRatio: number;
}

function toNumber(value: Decimal | number): number {
   if (typeof value === 'number') return value;
   return Number(value.toString());
}

function clamp(value: number, min: number, max: number): number {
   return Math.min(max, Math.max(min, value));
}

function round2(value: number): number {
   return Math.round(value * 100) / 100;
}

export function computeRemainingRatio(periodStart: Date, periodEnd: Date, now: Date): number {
   const periodMs = periodEnd.getTime() - periodStart.getTime();
   if (periodMs <= 0) return 0;
   const remainingMs = periodEnd.getTime() - now.getTime();
   return clamp(remainingMs / periodMs, 0, 1);
}

export function computeProration(input: ProrationInput): ProrationResult {
   const now = input.now ?? new Date();
   if (input.status === SubscriptionStatus.TRIALING) {
      return { prorationAmount: 0, remainingRatio: computeRemainingRatio(input.periodStart, input.periodEnd, now) };
   }
   const remainingRatio = computeRemainingRatio(input.periodStart, input.periodEnd, now);
   const oldPrice = toNumber(input.oldPrice);
   const newPrice = toNumber(input.newPrice);
   const delta = newPrice - oldPrice;
   const prorationAmount = round2(Math.max(0, delta * remainingRatio));
   return { prorationAmount, remainingRatio };
}
