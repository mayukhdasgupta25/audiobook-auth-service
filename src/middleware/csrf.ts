import { Request, Response, NextFunction } from 'express';
import { validateCsrfToken } from '../utils/csrf';
import { ClientType } from '../constants/clientType';

const CSRF_PROTECTED_PATHS = new Set(['/login', '/google', '/refresh', '/logout']);

export function requiresCsrfProtection(req: Request): boolean {
   const path = req.path;
   if (!CSRF_PROTECTED_PATHS.has(path)) {
      return false;
   }

   if (path === '/login' || path === '/google') {
      return req.body?.clientType === ClientType.BROWSER;
   }

   if (path === '/refresh' || path === '/logout') {
      return Boolean(req.cookies?.['refreshToken']);
   }

   return false;
}

export function validateCsrf(req: Request, res: Response, next: NextFunction): void {
   if (!requiresCsrfProtection(req)) {
      next();
      return;
   }

   const headerToken = req.get('X-CSRF-Token');
   const cookieToken = req.cookies?.['csrfToken'];

   if (!validateCsrfToken(headerToken, cookieToken)) {
      res.status(403).json({
         error: 'Invalid CSRF token',
         code: 'CSRF_VALIDATION_FAILED',
      });
      return;
   }

   next();
}
