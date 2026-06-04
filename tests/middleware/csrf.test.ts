import { Request, Response, NextFunction } from 'express';
import { requiresCsrfProtection, validateCsrf } from '../../src/middleware/csrf';

function createMockRequest(overrides: Partial<Request> = {}): Request {
   return {
      path: '/login',
      body: {},
      cookies: {},
      get: jest.fn(),
      ...overrides,
   } as unknown as Request;
}

function createMockResponse(): Response {
   const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
   };
   return res as unknown as Response;
}

describe('requiresCsrfProtection', () => {
   test('requires CSRF for browser login', () => {
      const req = createMockRequest({
         path: '/login',
         body: { clientType: 'browser' },
      });
      expect(requiresCsrfProtection(req)).toBe(true);
   });

   test('skips CSRF for mobile login', () => {
      const req = createMockRequest({
         path: '/login',
         body: { clientType: 'mobile' },
      });
      expect(requiresCsrfProtection(req)).toBe(false);
   });

   test('skips CSRF for login without clientType', () => {
      const req = createMockRequest({ path: '/login', body: {} });
      expect(requiresCsrfProtection(req)).toBe(false);
   });

   test('requires CSRF for browser google OAuth', () => {
      const req = createMockRequest({
         path: '/google',
         body: { clientType: 'browser' },
      });
      expect(requiresCsrfProtection(req)).toBe(true);
   });

   test('requires CSRF for cookie-based refresh', () => {
      const req = createMockRequest({
         path: '/refresh',
         cookies: { refreshToken: 'token' },
      });
      expect(requiresCsrfProtection(req)).toBe(true);
   });

   test('skips CSRF for body-only refresh', () => {
      const req = createMockRequest({
         path: '/refresh',
         body: { refreshToken: 'token' },
      });
      expect(requiresCsrfProtection(req)).toBe(false);
   });

   test('requires CSRF for cookie-based logout', () => {
      const req = createMockRequest({
         path: '/logout',
         cookies: { refreshToken: 'token' },
      });
      expect(requiresCsrfProtection(req)).toBe(true);
   });

   test('skips CSRF for body-only logout', () => {
      const req = createMockRequest({
         path: '/logout',
         body: { refreshToken: 'token' },
      });
      expect(requiresCsrfProtection(req)).toBe(false);
   });

   test('skips CSRF for unrelated paths', () => {
      const req = createMockRequest({ path: '/register' });
      expect(requiresCsrfProtection(req)).toBe(false);
   });
});

describe('validateCsrf', () => {
   let mockNext: NextFunction;

   beforeEach(() => {
      mockNext = jest.fn();
   });

   test('calls next when CSRF not required', () => {
      const req = createMockRequest({
         path: '/login',
         body: { clientType: 'mobile' },
      });
      const res = createMockResponse();

      validateCsrf(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
   });

   test('calls next when header matches cookie', () => {
      const token = 'a'.repeat(64);
      const req = createMockRequest({
         path: '/login',
         body: { clientType: 'browser' },
         cookies: { csrfToken: token },
      });
      (req.get as jest.Mock).mockReturnValue(token);
      const res = createMockResponse();

      validateCsrf(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
   });

   test('returns 403 when header is missing', () => {
      const req = createMockRequest({
         path: '/refresh',
         cookies: { refreshToken: 'rt', csrfToken: 'a'.repeat(64) },
      });
      (req.get as jest.Mock).mockReturnValue(undefined);
      const res = createMockResponse();

      validateCsrf(req, res, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
         error: 'Invalid CSRF token',
         code: 'CSRF_VALIDATION_FAILED',
      });
   });

   test('returns 403 when cookie is missing', () => {
      const req = createMockRequest({
         path: '/logout',
         cookies: { refreshToken: 'rt' },
      });
      (req.get as jest.Mock).mockReturnValue('a'.repeat(64));
      const res = createMockResponse();

      validateCsrf(req, res, mockNext);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
         error: 'Invalid CSRF token',
         code: 'CSRF_VALIDATION_FAILED',
      });
   });

   test('returns 403 when header and cookie mismatch', () => {
      const req = createMockRequest({
         path: '/login',
         body: { clientType: 'browser' },
         cookies: { csrfToken: 'a'.repeat(64) },
      });
      (req.get as jest.Mock).mockReturnValue('b'.repeat(64));
      const res = createMockResponse();

      validateCsrf(req, res, mockNext);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
         error: 'Invalid CSRF token',
         code: 'CSRF_VALIDATION_FAILED',
      });
   });
});
