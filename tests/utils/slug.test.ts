import { normalizeSlugBase } from '../../src/utils/slug';

describe('slug utils', () => {
   it('normalizes organization names into slug bases', () => {
      expect(normalizeSlugBase('Acme Publishing')).toBe('acme-publishing');
      expect(normalizeSlugBase('  Hello   World!! ')).toBe('hello-world');
   });
});
