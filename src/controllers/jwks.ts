import { Request, Response } from 'express';
import crypto from 'crypto';
import { CryptoUtils } from '../utils/crypto';
import { config } from '../config/env';
import { redisService } from '../services/redis';

/**
 * JWKS controller for providing public keys for JWT verification
 */
export class JWKSController {
   /**
    * Get JWKS (JSON Web Key Set) with Redis caching and automatic key rotation detection
    */
   async getJWKS(_req: Request, res: Response): Promise<void> {
      try {
         // Generate hash of current JWT public key for key rotation detection
         const currentKeyHash = crypto
            .createHash('sha256')
            .update(config.JWT_PUBLIC_KEY)
            .digest('hex');

         // Check if keys have been rotated
         let storedKeyHash: string | null = null;
         try {
            storedKeyHash = await redisService.getKeyHash();
         } catch (error) {
            if (config.NODE_ENV !== 'test') {
               console.warn('Failed to get key hash from Redis, continuing without cache:', error);
            }
         }

         // If key hash has changed, invalidate the cache
         if (storedKeyHash && storedKeyHash !== currentKeyHash) {
            console.log('Key rotation detected, invalidating JWKS cache');
            try {
               await redisService.invalidateJWKSCache();
            } catch (error) {
               console.error('Failed to invalidate cache:', error);
            }
         }

         // Try to get cached JWKS
         let jwks = null;
         try {
            jwks = await redisService.getCachedJWKS();
            if (jwks) {
               console.log('JWKS cache hit');
            } else {
               console.log('JWKS cache miss');
            }
         } catch (error) {
            if (config.NODE_ENV !== 'test') {
               console.warn('Failed to get cached JWKS, generating new one:', error);
            }
         }

         // If not cached, generate new JWKS
         if (!jwks) {
            jwks = CryptoUtils.generateJWKS(config.JWT_PUBLIC_KEY, config.JWT_KEY_ID);

            // Cache the JWKS for 1 hour
            try {
               await redisService.cacheJWKS(jwks, 3600);
               console.log('JWKS cached successfully');
            } catch (error) {
               if (config.NODE_ENV !== 'test') {
                  console.warn('Failed to cache JWKS, continuing without cache:', error);
               }
            }
         }

         // Store current key hash if not stored or different
         if (!storedKeyHash || storedKeyHash !== currentKeyHash) {
            try {
               await redisService.storeKeyHash(currentKeyHash);
               console.log('Key hash updated');
            } catch (error) {
               if (config.NODE_ENV !== 'test') {
                  console.warn('Failed to store key hash:', error);
               }
            }
         }

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
      } catch (_error) {
         res.status(500).json({
            status: 'unhealthy',
            error: 'Health check failed',
         });
      }
   }
}

export const jwksController = new JWKSController();
