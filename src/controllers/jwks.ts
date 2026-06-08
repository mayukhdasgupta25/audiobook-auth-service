import { Request, Response } from 'express';
import crypto from 'crypto';
import { CryptoUtils } from '../utils/crypto';
import { config } from '../config/env';
import { redisService } from '../services/redis';
import { appLogger, redisLogger } from '../utils/logger';

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
               redisLogger.warn({ err: error }, 'Failed to get key hash from Redis, continuing without cache');
            }
         }

         // If key hash has changed, invalidate the cache
         if (storedKeyHash && storedKeyHash !== currentKeyHash) {
            appLogger.info('Key rotation detected, invalidating JWKS cache');
            try {
               await redisService.invalidateJWKSCache();
            } catch (error) {
               redisLogger.error({ err: error }, 'Failed to invalidate JWKS cache');
            }
         }

         // Try to get cached JWKS
         let jwks = null;
         try {
            jwks = await redisService.getCachedJWKS();
            if (jwks) {
               redisLogger.info('JWKS cache hit');
            } else {
               redisLogger.info('JWKS cache miss');
            }
         } catch (error) {
            if (config.NODE_ENV !== 'test') {
               redisLogger.warn({ err: error }, 'Failed to get cached JWKS, generating new one');
            }
         }

         // If not cached, generate new JWKS
         if (!jwks) {
            jwks = CryptoUtils.generateJWKS(config.JWT_PUBLIC_KEY, config.JWT_KEY_ID);

            // Cache the JWKS for 1 hour
            try {
               await redisService.cacheJWKS(jwks, 3600);
               redisLogger.info('JWKS cached successfully');
            } catch (error) {
               if (config.NODE_ENV !== 'test') {
                  redisLogger.warn({ err: error }, 'Failed to cache JWKS, continuing without cache');
               }
            }
         }

         // Store current key hash if not stored or different
         if (!storedKeyHash || storedKeyHash !== currentKeyHash) {
            try {
               await redisService.storeKeyHash(currentKeyHash);
               redisLogger.info('Key hash updated');
            } catch (error) {
               if (config.NODE_ENV !== 'test') {
                  redisLogger.warn({ err: error }, 'Failed to store key hash');
               }
            }
         }

         // Set appropriate headers
         res.setHeader('Content-Type', 'application/json');
         res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour

         res.json(jwks);
      } catch (error) {
         appLogger.error({ err: error }, 'Failed to generate JWKS');
         res.status(500).json({
            error: 'Failed to generate JWKS',
         });
      }
   }
}

export const jwksController = new JWKSController();
