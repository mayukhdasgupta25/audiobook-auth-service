import crypto from 'crypto';
import { CookieOptions } from 'express-serve-static-core';
import { config } from '../config/env';

const CSRF_TOKEN_BYTES = 32;
const CSRF_COOKIE_MAX_AGE = 24 * 60 * 60 * 1000;

export function generateCsrfToken(): string {
   return crypto.randomBytes(CSRF_TOKEN_BYTES).toString('hex');
}

export function getCsrfCookieOptions(maxAge = CSRF_COOKIE_MAX_AGE): CookieOptions {
   return {
      httpOnly: true,
      secure: config.USE_SECURE_COOKIES,
      sameSite: config.USE_SECURE_COOKIES ? 'strict' : 'lax',
      path: '/',
      maxAge,
   };
}

export function validateCsrfToken(header: string | undefined, cookie: string | undefined): boolean {
   if (!header || !cookie) {
      return false;
   }

   if (header.length !== cookie.length) {
      return false;
   }

   try {
      return crypto.timingSafeEqual(Buffer.from(header), Buffer.from(cookie));
   } catch {
      return false;
   }
}
