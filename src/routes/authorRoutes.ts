import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import { AuthorController } from '../controllers/AuthorController';
import { OrganizationController } from '../controllers/OrganizationController';
import { requireRole } from '../middleware';
import { AuthRoleGroups } from '../constants/authRoles';

export function createAuthorRoutes(prisma: PrismaClient): Router {
   const router = Router();
   const authorController = new AuthorController(prisma);
   const organizationController = new OrganizationController(prisma);

   router.get('/me', authorController.getMyAuthor);
   router.get(
      '/:authorId/organizations/:organizationId/link',
      organizationController.checkAuthorOrganizationLink,
   );
   router.get('/', authorController.getAllAuthors);
   router.get('/:id', authorController.getAuthorById);
   router.post('/', requireRole([...AuthRoleGroups.GLOBAL_ADMIN_OR_AUTHOR]), authorController.createAuthor);
   router.put('/:id', requireRole([...AuthRoleGroups.GLOBAL_ADMIN_OR_AUTHOR]), authorController.updateAuthor);
   router.delete('/:id', requireRole([...AuthRoleGroups.GLOBAL_ADMIN_OR_AUTHOR]), authorController.deleteAuthor);

   return router;
}
