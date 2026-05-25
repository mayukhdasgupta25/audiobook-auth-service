import {
   formatSubscriptionPlanFeatures,
   resetSubscriptionPlanFeatureTranslationsCache,
} from '../../src/utils/formatSubscriptionPlanFeatures';
import { SubscriptionPlanFeatures } from '../../src/types/subscriptionPlanFeatures';

const baseFeatures: SubscriptionPlanFeatures = {
   audiobookCatalog: 'selected',
   maxDevices: 1,
   audioQuality: 'base',
   deviceChangesPerMonth: 0,
};

const standardFeatures: SubscriptionPlanFeatures = {
   audiobookCatalog: 'curated_wide',
   maxDevices: 2,
   audioQuality: 'high',
   deviceChangesPerMonth: 1,
};

const premiumFeatures: SubscriptionPlanFeatures = {
   audiobookCatalog: 'all',
   maxDevices: 3,
   audioQuality: 'best',
   deviceChangesPerMonth: 3,
};

describe('formatSubscriptionPlanFeatures', () => {
   beforeEach(() => {
      resetSubscriptionPlanFeatureTranslationsCache();
   });

   it('returns empty array for null or invalid features', () => {
      expect(formatSubscriptionPlanFeatures(null)).toEqual([]);
      expect(formatSubscriptionPlanFeatures([])).toEqual([]);
      expect(formatSubscriptionPlanFeatures('text')).toEqual([]);
   });

   it('formats Base plan features without device change line', () => {
      expect(formatSubscriptionPlanFeatures(baseFeatures)).toEqual([
         'Selected range of audiobook titles',
         'Available on 1 device',
         'Base audio quality',
      ]);
   });

   it('formats Standard plan features', () => {
      expect(formatSubscriptionPlanFeatures(standardFeatures)).toEqual([
         'Wide range of curated audiobook titles',
         'Available on 2 devices',
         'Higher audio quality',
         'Add/remove devices 1 time a month',
      ]);
   });

   it('formats Premium plan features', () => {
      expect(formatSubscriptionPlanFeatures(premiumFeatures)).toEqual([
         'All audiobook titles available',
         'Available on 3 devices',
         'Best audio quality',
         'Add/remove devices 3 times a month',
      ]);
   });
});
