import { createClient, RedisClientType } from 'redis';
import { config } from '../config/env';
import { RevokedToken, JWKS } from '../types';

/**
 * Redis service for token revocation and blocklist management
 */
export class RedisService {
   private client: RedisClientType;
   private isConnected: boolean = false;

   constructor() {
      this.client = createClient({
         url: config.REDIS_URL,
      });

      this.client.on('error', (err) => {
         console.error('Redis Client Error:', err);
         this.isConnected = false;
      });

      this.client.on('connect', () => {
         console.log('Redis Client Connected');
         this.isConnected = true;
      });

      this.client.on('disconnect', () => {
         console.log('Redis Client Disconnected');
         this.isConnected = false;
      });
   }

   /**
    * Connect to Redis
    */
   async connect(): Promise<void> {
      if (!this.isConnected) {
         await this.client.connect();
      }
   }

   /**
    * Disconnect from Redis
    */
   async disconnect(): Promise<void> {
      if (this.isConnected) {
         await this.client.disconnect();
      }
   }

   /**
    * Add a token to the blocklist
    */
   async revokeToken(jti: string, userId: string, reason?: string): Promise<void> {
      try {
         const revokedToken: RevokedToken = {
            jti,
            userId,
            revokedAt: new Date(),
            ...(reason && { reason }),
         };

         // Store with TTL of 10 minutes (access token expiry)
         await this.client.setEx(
            `revoked:${jti}`,
            600, // 10 minutes in seconds
            JSON.stringify(revokedToken)
         );

         console.log(`Token ${jti} revoked for user ${userId}`);
      } catch (error) {
         console.error('Failed to revoke token:', error);
         throw new Error('Failed to revoke token');
      }
   }

   /**
    * Check if a token is revoked
    */
   async isTokenRevoked(jti: string): Promise<boolean> {
      try {
         const result = await this.client.get(`revoked:${jti}`);
         return result !== null;
      } catch (error) {
         console.error('Failed to check token revocation:', error);
         // In case of Redis error, assume token is not revoked to avoid blocking valid users
         return false;
      }
   }

   /**
    * Get revoked token details
    */
   async getRevokedToken(jti: string): Promise<RevokedToken | null> {
      try {
         const result = await this.client.get(`revoked:${jti}`);
         if (!result) {
            return null;
         }
         return JSON.parse(result) as RevokedToken;
      } catch (error) {
         console.error('Failed to get revoked token:', error);
         return null;
      }
   }

   /**
    * Revoke all tokens for a user (emergency revoke)
    */
   async revokeAllUserTokens(userId: string, reason: string = 'Emergency revoke'): Promise<void> {
      try {
         // This would require scanning all keys, which is expensive
         // In production, you might want to maintain a separate index
         // For now, we'll log this action and let tokens expire naturally
         console.log(`Emergency revoke requested for user ${userId}: ${reason}`);

         // Store a marker for this user's emergency revoke
         await this.client.setEx(
            `emergency_revoke:${userId}`,
            3600, // 1 hour
            JSON.stringify({
               userId,
               revokedAt: new Date(),
               reason,
            })
         );
      } catch (error) {
         console.error('Failed to emergency revoke user tokens:', error);
         throw new Error('Failed to emergency revoke user tokens');
      }
   }

   /**
    * Check if user has emergency revoke
    */
   async hasEmergencyRevoke(userId: string): Promise<boolean> {
      try {
         const result = await this.client.get(`emergency_revoke:${userId}`);
         return result !== null;
      } catch (error) {
         console.error('Failed to check emergency revoke:', error);
         return false;
      }
   }

   /**
    * Store PKCE session data
    */
   async storePKCESession(sessionId: string, data: any, ttl: number = 600): Promise<void> {
      try {
         await this.client.setEx(
            `pkce:${sessionId}`,
            ttl,
            JSON.stringify(data)
         );
      } catch (error) {
         console.error('Failed to store PKCE session:', error);
         throw new Error('Failed to store PKCE session');
      }
   }

   /**
    * Get PKCE session data
    */
   async getPKCESession(sessionId: string): Promise<any | null> {
      try {
         const result = await this.client.get(`pkce:${sessionId}`);
         if (!result) {
            return null;
         }
         return JSON.parse(result);
      } catch (error) {
         console.error('Failed to get PKCE session:', error);
         return null;
      }
   }

   /**
    * Delete PKCE session data
    */
   async deletePKCESession(sessionId: string): Promise<void> {
      try {
         await this.client.del(`pkce:${sessionId}`);
      } catch (error) {
         console.error('Failed to delete PKCE session:', error);
      }
   }

   /**
    * Cache JWKS (JSON Web Key Set) in Redis
    */
   async cacheJWKS(jwks: JWKS, ttl: number = 3600): Promise<void> {
      try {
         await this.client.setEx('jwks:current', ttl, JSON.stringify(jwks));
      } catch (error) {
         console.error('Failed to cache JWKS:', error);
         throw new Error('Failed to cache JWKS');
      }
   }

   /**
    * Get cached JWKS from Redis
    */
   async getCachedJWKS(): Promise<JWKS | null> {
      try {
         const result = await this.client.get('jwks:current');
         if (!result) {
            return null;
         }
         return JSON.parse(result) as JWKS;
      } catch (error) {
         console.error('Failed to get cached JWKS:', error);
         return null;
      }
   }

   /**
    * Invalidate JWKS cache
    */
   async invalidateJWKSCache(): Promise<void> {
      try {
         await this.client.del('jwks:current');
         console.log('JWKS cache invalidated');
      } catch (error) {
         console.error('Failed to invalidate JWKS cache:', error);
      }
   }

   /**
    * Store key hash for key rotation detection
    */
   async storeKeyHash(keyHash: string): Promise<void> {
      try {
         // Store without TTL (persistent until key rotation)
         await this.client.set('jwks:key_hash', keyHash);
         console.log('Key hash stored successfully');
      } catch (error) {
         console.error('Failed to store key hash:', error);
      }
   }

   /**
    * Get stored key hash
    */
   async getKeyHash(): Promise<string | null> {
      try {
         const result = await this.client.get('jwks:key_hash');
         return result;
      } catch (error) {
         console.error('Failed to get key hash:', error);
         return null;
      }
   }

   /**
    * Health check
    */
   async healthCheck(): Promise<boolean> {
      try {
         await this.client.ping();
         return true;
      } catch (error) {
         return false;
      }
   }
}

// Singleton instance
export const redisService = new RedisService();
