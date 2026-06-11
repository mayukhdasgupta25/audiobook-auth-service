import { parsePhoneNumberFromString } from 'libphonenumber-js';

export const DEFAULT_PHONE_REGION = 'IN' as const;

export interface IndianContactValidationResult {
   errors: string[];
   normalized?: string;
}

export function validateIndianContact(contact: string): IndianContactValidationResult {
   const trimmed = contact.trim();

   if (trimmed.length === 0) {
      return { errors: ['Contact must be a valid Indian phone number'] };
   }

   const phone = parsePhoneNumberFromString(trimmed, DEFAULT_PHONE_REGION);

   if (!phone || !phone.isValid() || phone.country !== DEFAULT_PHONE_REGION) {
      return { errors: ['Contact must be a valid Indian phone number'] };
   }

   return {
      errors: [],
      normalized: phone.format('E.164'),
   };
}
