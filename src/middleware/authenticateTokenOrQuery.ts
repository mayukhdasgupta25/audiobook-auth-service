import { Request, Response, NextFunction } from 'express';
import { JWTUtils } from '../utils/crypto';
import { redisService } from '../services/redis';

/**
 * Authenticates SSE requests via Authorization header or ?access_token= query param.
 */
export const authenticateTokenOrQuery = async (
   req: Request,
   res: Response,
   next: NextFunction,
): Promise<void> => {
   try {
      const authHeader = req.headers.authorization;
      const headerToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined;
      const queryToken =
         typeof req.query['access_token'] === 'string' && req.query['access_token'].trim().length > 0
            ? req.query['access_token'].trim()
            : undefined;
      const token = headerToken ?? queryToken;

      if (!token) {
         res.status(401).json({ error: 'Access token required' });
         return;
      }

      const payload = JWTUtils.verifyAccessToken(token);

      const isRevoked = await redisService.isTokenRevoked(payload.jti);
      if (isRevoked) {
         res.status(401).json({ error: 'Token has been revoked' });
         return;
      }

      const hasEmergencyRevoke = await redisService.hasEmergencyRevoke(payload.sub);
      if (hasEmergencyRevoke) {
         res.status(401).json({ error: 'Account access revoked' });
         return;
      }

      (req as Request & { user?: { id: string; email: string; role: string } }).user = {
         id: payload.sub,
         email: payload.email,
         role: payload.role,
      };
      (req as Request & { token?: string }).token = token;

      next();
   } catch {
      res.status(401).json({ error: 'Invalid or expired token' });
   }
};
