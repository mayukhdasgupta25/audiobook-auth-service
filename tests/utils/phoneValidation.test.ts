import { validateIndianContact } from '../../src/utils/phoneValidation';

describe('validateIndianContact', () => {
   test('accepts 10-digit Indian mobile number and normalizes to E.164', () => {
      const result = validateIndianContact('9876543210');

      expect(result.errors).toEqual([]);
      expect(result.normalized).toBe('+919876543210');
   });

   test('accepts +91 formatted number and normalizes to E.164', () => {
      const result = validateIndianContact('+91 98765 43210');

      expect(result.errors).toEqual([]);
      expect(result.normalized).toBe('+919876543210');
   });

   test('accepts leading-zero national format and normalizes to E.164', () => {
      const result = validateIndianContact('09876543210');

      expect(result.errors).toEqual([]);
      expect(result.normalized).toBe('+919876543210');
   });

   test('rejects empty contact', () => {
      const result = validateIndianContact('   ');

      expect(result.errors).toEqual(['Contact must be a valid Indian phone number']);
      expect(result.normalized).toBeUndefined();
   });

   test('rejects too-short number', () => {
      const result = validateIndianContact('12345');

      expect(result.errors).toEqual(['Contact must be a valid Indian phone number']);
      expect(result.normalized).toBeUndefined();
   });

   test('rejects non-numeric contact', () => {
      const result = validateIndianContact('not-a-phone');

      expect(result.errors).toEqual(['Contact must be a valid Indian phone number']);
      expect(result.normalized).toBeUndefined();
   });

   test('rejects valid non-Indian number', () => {
      const result = validateIndianContact('+1-555-0100');

      expect(result.errors).toEqual(['Contact must be a valid Indian phone number']);
      expect(result.normalized).toBeUndefined();
   });
});
