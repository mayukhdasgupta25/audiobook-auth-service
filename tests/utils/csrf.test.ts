import { generateCsrfToken, validateCsrfToken } from '../../src/utils/csrf';

describe('csrf utils', () => {
   test('generateCsrfToken returns 64 hex characters', () => {
      const token = generateCsrfToken();
      expect(token).toMatch(/^[a-f0-9]{64}$/);
   });

   test('validateCsrfToken accepts matching header and cookie', () => {
      const token = generateCsrfToken();
      expect(validateCsrfToken(token, token)).toBe(true);
   });

   test('validateCsrfToken rejects missing values', () => {
      const token = generateCsrfToken();
      expect(validateCsrfToken(undefined, token)).toBe(false);
      expect(validateCsrfToken(token, undefined)).toBe(false);
   });

   test('validateCsrfToken rejects mismatched tokens', () => {
      const token = generateCsrfToken();
      expect(validateCsrfToken(token, 'b'.repeat(64))).toBe(false);
   });

   test('validateCsrfToken rejects different lengths', () => {
      expect(validateCsrfToken('short', 'longer')).toBe(false);
   });
});
