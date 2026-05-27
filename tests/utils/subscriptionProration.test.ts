import { SubscriptionStatus } from '@prisma/client';
import { computeProration, computeRemainingRatio } from '../../src/utils/subscriptionProration';

describe('subscriptionProration', () => {
   const periodStart = new Date('2026-01-01T00:00:00.000Z');
   const periodEnd = new Date('2026-02-01T00:00:00.000Z');

   describe('computeRemainingRatio', () => {
      it('returns 0.5 when half the period remains', () => {
         const now = new Date('2026-01-16T12:00:00.000Z');
         expect(computeRemainingRatio(periodStart, periodEnd, now)).toBeCloseTo(0.5, 2);
      });

      it('returns 0 when period has ended', () => {
         const now = new Date('2026-02-02T00:00:00.000Z');
         expect(computeRemainingRatio(periodStart, periodEnd, now)).toBe(0);
      });

      it('returns 1 at period start', () => {
         expect(computeRemainingRatio(periodStart, periodEnd, periodStart)).toBe(1);
      });
   });

   describe('computeProration', () => {
      it('charges half the price delta when half the period remains', () => {
         const now = new Date('2026-01-16T12:00:00.000Z');
         const result = computeProration({
            oldPrice: 100,
            newPrice: 200,
            periodStart,
            periodEnd,
            now,
         });
         expect(result.prorationAmount).toBe(50);
         expect(result.remainingRatio).toBeCloseTo(0.5, 2);
      });

      it('returns 0 when no time remains in the period', () => {
         const now = new Date('2026-02-02T00:00:00.000Z');
         const result = computeProration({
            oldPrice: 100,
            newPrice: 200,
            periodStart,
            periodEnd,
            now,
         });
         expect(result.prorationAmount).toBe(0);
      });

      it('never returns negative proration (downgrade path should not use this for charge)', () => {
         const now = new Date('2026-01-16T12:00:00.000Z');
         const result = computeProration({
            oldPrice: 200,
            newPrice: 100,
            periodStart,
            periodEnd,
            now,
         });
         expect(result.prorationAmount).toBe(0);
      });

      it('returns 0 during trial regardless of price delta', () => {
         const now = new Date('2026-01-16T12:00:00.000Z');
         const result = computeProration({
            oldPrice: 100,
            newPrice: 300,
            periodStart,
            periodEnd,
            now,
            status: SubscriptionStatus.TRIALING,
         });
         expect(result.prorationAmount).toBe(0);
      });
   });
});
