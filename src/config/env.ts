import dotenv from "dotenv";
import path from "path";

const nodeEnv = process.env['NODE_ENV'] || 'development';
const envFile = `.env${nodeEnv !== 'development' ? `.${nodeEnv}` : ''}`;
dotenv.config({ path: path.resolve(process.cwd(), envFile) });

// Load .env.local for local overrides (highest priority)
dotenv.config({ path: path.resolve(process.cwd(), '.env.local') });

export const config = {
   NODE_ENV: nodeEnv,
   PORT: parseInt(process.env['PORT'] || '8080', 10),

   // Database
   DATABASE_URL: process.env['DATABASE_URL'] || '',

   // Redis
   REDIS_URL: process.env['REDIS_URL'] || 'redis://localhost:6379',

   // RabbitMQ
   RABBITMQ_URL: process.env['RABBITMQ_URL'] || 'amqp://localhost:5672',
   RABBITMQ_EXCHANGE: process.env['RABBITMQ_EXCHANGE'] || 'users',

   // JWT Configuration
   JWT_PRIVATE_KEY: process.env['JWT_PRIVATE_KEY'] || '',
   JWT_PUBLIC_KEY: process.env['JWT_PUBLIC_KEY'] || '',
   JWT_KEY_ID: process.env['JWT_KEY_ID'] || 'auth-service-key-1',
   JWT_ISSUER: process.env['JWT_ISSUER'] || 'auth-service',
   JWT_ACCESS_TOKEN_EXPIRY: '7d',
   JWT_REFRESH_TOKEN_EXPIRY: '7d',

   // CORS Configuration
   CORS_ORIGINS: process.env['CORS_ORIGINS']?.split(',') || ['http://192.168.1.9:3000', 'http://localhost:8081', 'http://localhost:8082', 'http://localhost:3001'],

   // Rate Limiting
   RATE_LIMIT_WINDOW_MS: parseInt(process.env['RATE_LIMIT_WINDOW_MS'] || '900000', 10),
   RATE_LIMIT_MAX_REQUESTS: parseInt(process.env['RATE_LIMIT_MAX_REQUESTS'] || '100', 10),

   // Email Configuration
   EMAIL_FROM: process.env['EMAIL_FROM'] || 'noreply@audiobook.com',
   EMAIL_SERVICE_URL: process.env['EMAIL_SERVICE_URL'] || '',

   // Google OAuth Configuration
   GOOGLE_CLIENT_ID: process.env['GOOGLE_CLIENT_ID'] || '',

   // Security Configuration
   ARGON2_MEMORY: parseInt(process.env['ARGON2_MEMORY'] || '65536', 10),
   ARGON2_ITERATIONS: parseInt(process.env['ARGON2_ITERATIONS'] || '3', 10),
   ARGON2_PARALLELISM: parseInt(process.env['ARGON2_PARALLELISM'] || '4', 10),

   // Logging
   LOG_LEVEL: process.env['LOG_LEVEL'] || 'info',
};

// Validate required environment variables (skip in test environment)
// In test environment, env vars are set in tests/setup.ts before this module loads
const requiredEnvVars = ['DATABASE_URL', 'JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY', 'RABBITMQ_URL'];

if (nodeEnv !== 'test') {
   for (const envVar of requiredEnvVars) {
      if (!process.env[envVar]) {
         throw new Error(`Missing required environment variable: ${envVar}`);
      }
   }
}