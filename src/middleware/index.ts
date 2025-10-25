import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { JWTUtils } from '../utils/crypto';
import { redisService } from '../services/redis';
import { config } from '../config/env';
import { AuthError, ValidationError } from '../types';

/**
 * Authentication middleware
 */
export const authenticateToken = async (
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void> => {
   try {
      const authHeader = req.headers.authorization;
      const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

      if (!token) {
         res.status(401).json({ error: 'Access token required' });
         return;
      }

      // Verify token
      const payload = JWTUtils.verifyAccessToken(token);

      // Check if token is revoked
      const isRevoked = await redisService.isTokenRevoked(payload.jti);
      if (isRevoked) {
         res.status(401).json({ error: 'Token has been revoked' });
         return;
      }

      // Check for emergency revoke
      const hasEmergencyRevoke = await redisService.hasEmergencyRevoke(payload.sub);
      if (hasEmergencyRevoke) {
         res.status(401).json({ error: 'Account access revoked' });
         return;
      }

      // Attach user info to request
      (req as any).user = {
         id: payload.sub,
         email: payload.email,
         role: payload.role,
      };
      (req as any).token = token;

      next();
   } catch (error) {
      res.status(401).json({ error: 'Invalid or expired token' });
   }
};

/**
 * Role-based authorization middleware
 */
export const requireRole = (roles: string[]) => {
   return (req: Request, res: Response, next: NextFunction): void => {
      const authReq = req as any;
      if (!authReq.user) {
         res.status(401).json({ error: 'Authentication required' });
         return;
      }

      if (!roles.includes(authReq.user.role)) {
         res.status(403).json({ error: 'Insufficient permissions' });
         return;
      }

      next();
   };
};

/**
 * Admin only middleware
 */
export const requireAdmin = requireRole(['ADMIN']);

/**
 * Rate limiting middleware for login attempts
 */
export const loginRateLimit = rateLimit({
   windowMs: 15 * 60 * 1000, // 15 minutes
   max: 5, // 5 attempts per window
   message: {
      error: 'Too many login attempts, please try again later',
   },
   standardHeaders: true,
   legacyHeaders: false,
   skipSuccessfulRequests: true,
});

/**
 * Rate limiting middleware for password reset
 */
export const passwordResetRateLimit = rateLimit({
   windowMs: 60 * 60 * 1000, // 1 hour
   max: 3, // 3 attempts per hour
   message: {
      error: 'Too many password reset attempts, please try again later',
   },
   standardHeaders: true,
   legacyHeaders: false,
});

/**
 * Rate limiting middleware for registration
 */
export const registerRateLimit = rateLimit({
   windowMs: 60 * 60 * 1000, // 1 hour
   max: 10, // 10 registrations per hour
   message: {
      error: 'Too many registration attempts, please try again later',
   },
   standardHeaders: true,
   legacyHeaders: false,
});

/**
 * General rate limiting middleware
 */
export const generalRateLimit = rateLimit({
   windowMs: config.RATE_LIMIT_WINDOW_MS,
   max: config.RATE_LIMIT_MAX_REQUESTS,
   message: {
      error: 'Too many requests, please try again later',
   },
   standardHeaders: true,
   legacyHeaders: false,
});

/**
 * Error handling middleware
 */
export const errorHandler = (
   error: Error,
   _req: Request,
   res: Response,
   _next: NextFunction
): void => {
   console.error('Error:', error);

   // Handle specific error types
   if (error instanceof ValidationError) {
      res.status(error.statusCode).json({
         error: error.message,
         code: error.code,
         details: error.details,
      });
      return;
   }

   if (error instanceof AuthError) {
      res.status(error.statusCode).json({
         error: error.message,
         code: error.code,
      });
      return;
   }

   // Handle Prisma errors
   if (error.name === 'PrismaClientKnownRequestError') {
      const prismaError = error as any;
      if (prismaError.code === 'P2002') {
         res.status(409).json({
            error: 'Resource already exists',
            code: 'DUPLICATE_RESOURCE',
         });
         return;
      }
   }

   // Handle JWT errors
   if (error.name === 'JsonWebTokenError') {
      res.status(401).json({
         error: 'Invalid token',
         code: 'INVALID_TOKEN',
      });
      return;
   }

   if (error.name === 'TokenExpiredError') {
      res.status(401).json({
         error: 'Token expired',
         code: 'TOKEN_EXPIRED',
      });
      return;
   }

   // Default error response
   res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
   });
};

/**
 * Not found middleware
 */
export const notFound = (_req: Request, res: Response): void => {
   res.status(404).json({
      error: 'Route not found',
      code: 'NOT_FOUND',
   });
};

/**
 * Request logging middleware
 */
export const requestLogger = (req: Request, res: Response, next: NextFunction): void => {
   const start = Date.now();

   res.on('finish', () => {
      const duration = Date.now() - start;
      console.log(`${req.method} ${req.path} ${res.statusCode} - ${duration}ms`);
   });

   next();
};

/**
 * CORS middleware configuration
 */
export const corsOptions = {
   origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
      // Allow requests with no origin (mobile apps, Postman, etc.)
      if (!origin) {
         return callback(null, true);
      }

      if (config.CORS_ORIGINS.includes(origin)) {
         callback(null, true);
      } else {
         callback(new Error('Not allowed by CORS'));
      }
   },
   credentials: true,
   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
   allowedHeaders: ['Content-Type', 'Authorization'],
};

/**
 * Security headers middleware
 */
export const securityHeaders = (_req: Request, res: Response, next: NextFunction): void => {
   // Prevent clickjacking
   res.setHeader('X-Frame-Options', 'DENY');

   // Prevent MIME type sniffing
   res.setHeader('X-Content-Type-Options', 'nosniff');

   // Enable XSS protection
   res.setHeader('X-XSS-Protection', '1; mode=block');

   // Strict Transport Security (only in production)
   if (config.NODE_ENV === 'production') {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
   }

   next();
};
