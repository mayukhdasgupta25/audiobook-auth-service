import { Request, Response } from 'express';
import { CryptoUtils } from '../utils/crypto';
import { config } from '../config/env';

/**
 * JWKS controller for providing public keys for JWT verification
 */
export class JWKSController {
   /**
    * Get JWKS (JSON Web Key Set)
    */
   async getJWKS(_req: Request, res: Response): Promise<void> {
      try {
         const jwks = CryptoUtils.generateJWKS(config.JWT_PUBLIC_KEY, config.JWT_KEY_ID);

         // Set appropriate headers
         res.setHeader('Content-Type', 'application/json');
         res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour

         res.json(jwks);
      } catch (error) {
         console.error('Failed to generate JWKS:', error);
         res.status(500).json({
            error: 'Failed to generate JWKS',
         });
      }
   }

   /**
    * Health check endpoint
    */
   async healthCheck(_req: Request, res: Response): Promise<void> {
      try {
         // Check if JWT keys are properly configured
         if (!config.JWT_PRIVATE_KEY || !config.JWT_PUBLIC_KEY) {
            res.status(503).json({
               status: 'unhealthy',
               error: 'JWT keys not configured',
            });
            return;
         }

         res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            service: 'auth-service',
            version: '1.0.0',
         });
      } catch (error) {
         res.status(500).json({
            status: 'unhealthy',
            error: 'Health check failed',
         });
      }
   }
}

export const jwksController = new JWKSController();
