export type AudiobookCatalogScope = 'selected' | 'curated_wide' | 'all';
export type AudioQualityTier = 'base' | 'high' | 'best';

export interface SubscriptionPlanFeatures {
   audiobookCatalog: AudiobookCatalogScope;
   maxDevices: number;
   audioQuality: AudioQualityTier;
   deviceChangesPerMonth: number;
}

export function isSubscriptionPlanFeatures(value: unknown): value is SubscriptionPlanFeatures {
   if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return false;
   }
   const record = value as Record<string, unknown>;
   return (
      typeof record['audiobookCatalog'] === 'string' &&
      typeof record['maxDevices'] === 'number' &&
      typeof record['audioQuality'] === 'string' &&
      typeof record['deviceChangesPerMonth'] === 'number'
   );
}
