import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';

const SLUG_MAX_BASE_LENGTH = 60;
const SLUG_HEX_SUFFIX_LENGTH = 8;
const SLUG_MAX_RETRIES = 10;

/**
 * Normalize a free-form string into a URL-safe slug base.
 */
export function normalizeSlugBase(input: string): string {
   return input
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, SLUG_MAX_BASE_LENGTH);
}

function randomHexSuffix(): string {
   return crypto.randomBytes(SLUG_HEX_SUFFIX_LENGTH / 2).toString('hex');
}

function buildSlug(base: string): string {
   const normalized = normalizeSlugBase(base);
   const prefix = normalized.length > 0 ? normalized : 'item';
   return `${prefix}-${randomHexSuffix()}`;
}

async function generateUniqueSlug(
   prisma: PrismaClient,
   base: string,
   table: 'organization' | 'author',
): Promise<string> {
   for (let attempt = 0; attempt < SLUG_MAX_RETRIES; attempt += 1) {
      const slug = buildSlug(base);

      const existing =
         table === 'organization'
            ? await prisma.organization.findUnique({ where: { slug }, select: { id: true } })
            : await prisma.author.findUnique({ where: { slug }, select: { id: true } });

      if (!existing) {
         return slug;
      }
   }

   throw new Error('Failed to generate unique slug');
}

export async function generateOrganizationSlug(
   prisma: PrismaClient,
   name: string,
): Promise<string> {
   return generateUniqueSlug(prisma, name, 'organization');
}

export async function generateAuthorSlug(
   prisma: PrismaClient,
   firstName: string,
   lastName: string,
): Promise<string> {
   const base = `${firstName} ${lastName}`.trim();
   return generateUniqueSlug(prisma, base, 'author');
}
