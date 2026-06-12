import { Author as PrismaAuthor, Prisma, User } from '@prisma/client';

export interface OrganizationSummary {
   id: string;
   name: string;
   slug: string;
}

export interface AuthorDto {
   id: string;
   userId: string;
   slug: string;
   firstName?: string | null;
   lastName?: string | null;
   address?: string | null;
   contact?: string | null;
   organizations?: OrganizationSummary[];
   createdAt: Date;
   updatedAt: Date;
}

export interface CreateAuthorDto {
   userId: string;
   firstName?: string;
   lastName?: string;
   address?: string;
   contact?: string;
   organizationIds?: string[];
}

export interface UpdateAuthorDto {
   firstName?: string;
   lastName?: string;
   address?: string;
   contact?: string;
   organizationIds?: string[];
}

type AuthorWithRelations = Prisma.AuthorGetPayload<{
   include: typeof authorInclude;
}>;

const authorInclude = {
   user: {
      select: {
         firstName: true,
         lastName: true,
         address: true,
         contact: true,
      },
   },
   organizations: {
      include: {
         organization: {
            select: {
               id: true,
               name: true,
               slug: true,
            },
         },
      },
   },
} as const;

export { authorInclude };

export function toAuthorDto(author: PrismaAuthor | AuthorWithRelations): AuthorDto {
   const user = 'user' in author ? (author.user as Pick<User, 'firstName' | 'lastName' | 'address' | 'contact'> | null) : null;

   const dto: AuthorDto = {
      id: author.id,
      userId: author.userId,
      slug: author.slug,
      firstName: user?.firstName ?? null,
      lastName: user?.lastName ?? null,
      address: user?.address ?? null,
      contact: user?.contact ?? null,
      createdAt: author.createdAt,
      updatedAt: author.updatedAt,
   };

   if ('organizations' in author) {
      dto.organizations = author.organizations.map((link) => ({
         id: link.organization.id,
         name: link.organization.name,
         slug: link.organization.slug,
      }));
   }

   return dto;
}
