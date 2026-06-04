import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';

interface FeatureTranslationsFile {
   displayOrder: string[];
   keys: Record<string, Record<string, string | null>>;
}

const TRANSLATIONS_PATH = path.resolve(
   __dirname,
   '../../config/subscription-plan-features.en.yml'
);

let cachedTranslations: FeatureTranslationsFile | null = null;

function loadTranslations(): FeatureTranslationsFile {
   if (!cachedTranslations) {
      const raw = fs.readFileSync(TRANSLATIONS_PATH, 'utf8');
      const parsed = yaml.load(raw) as FeatureTranslationsFile;
      if (!parsed?.displayOrder?.length || !parsed.keys) {
         throw new Error('Invalid subscription plan features translation file');
      }
      cachedTranslations = parsed;
   }
   return cachedTranslations;
}

function lookupTranslation(
   translations: Record<string, string | null>,
   value: string | number
): string | null {
   const lookupKey = String(value);
   const direct = translations[lookupKey];
   if (direct !== undefined) {
      return direct;
   }
   const fallback = translations['default'];
   if (fallback) {
      return fallback.replace(/\{\{value\}\}/g, lookupKey);
   }
   return null;
}

/**
 * Turns stored plan feature JSON into ordered, human-readable sentences for API responses.
 */
export function formatSubscriptionPlanFeatures(features: unknown): string[] {
   if (!features || typeof features !== 'object' || Array.isArray(features)) {
      return [];
   }

   const config = loadTranslations();
   const record = features as Record<string, unknown>;
   const sentences: string[] = [];

   for (const key of config.displayOrder) {
      if (!(key in record)) {
         continue;
      }
      const value = record[key];
      if (value === null || value === undefined) {
         continue;
      }
      if (typeof value !== 'string' && typeof value !== 'number') {
         continue;
      }

      const keyTranslations = config.keys[key];
      if (!keyTranslations) {
         continue;
      }

      const sentence = lookupTranslation(keyTranslations, value);
      if (sentence) {
         sentences.push(sentence);
      }
   }

   return sentences;
}

/** Clears cached YAML (for tests). */
export function resetSubscriptionPlanFeatureTranslationsCache(): void {
   cachedTranslations = null;
}
