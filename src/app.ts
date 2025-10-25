import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { config } from './config/env';
import authRoutes from './routes/auth';
import {
   errorHandler,
   notFound,
   requestLogger,
   corsOptions,
   securityHeaders
} from './middleware';
import { redisService } from './services/redis';
import { rabbitmqService } from './services/rabbitmq';

/**
 * Create and configure Express application
 */
export const createApp = (): express.Application => {
   const app = express();

   // Security middleware
   app.use(helmet());
   app.use(securityHeaders);

   // CORS configuration
   app.use(cors(corsOptions));

   // Body parsing middleware
   app.use(express.json({ limit: '10mb' }));
   app.use(express.urlencoded({ extended: true, limit: '10mb' }));
   app.use(cookieParser());

   // Request logging
   app.use(requestLogger);

   // Health check endpoint
   app.get('/health', (_req, res) => {
      res.json({
         status: 'healthy',
         timestamp: new Date().toISOString(),
         service: 'auth-service',
         version: '1.0.0',
      });
   });

   // API routes
   app.use('/auth', authRoutes);

   // Root endpoint
   app.get('/', (_req, res) => {
      res.json({
         message: 'Auth Service API',
         version: '1.0.0',
         endpoints: {
            health: '/health',
            auth: '/auth',
            jwks: '/auth/.well-known/jwks.json',
         },
      });
   });

   // Error handling middleware (must be last)
   app.use(notFound);
   app.use(errorHandler);

   return app;
};

/**
 * Initialize services and start the server
 */
export const startServer = async (): Promise<void> => {
   try {
      // Connect to RabbitMQ
      await rabbitmqService.connect();
      console.log('Connected to RabbitMQ');

      // Connect to Redis
      await redisService.connect();
      console.log('Connected to Redis');

      // Create Express app
      const app = createApp();

      // Start server
      const port = config.PORT;
      app.listen(port, () => {
         console.log(`Auth service running on port ${port}`);
         console.log(`Environment: ${config.NODE_ENV}`);
         console.log(`JWKS endpoint: http://localhost:${port}/auth/.well-known/jwks.json`);
      });

      // Graceful shutdown
      process.on('SIGTERM', async () => {
         console.log('SIGTERM received, shutting down gracefully');
         await rabbitmqService.disconnect();
         await redisService.disconnect();
         process.exit(0);
      });

      process.on('SIGINT', async () => {
         console.log('SIGINT received, shutting down gracefully');
         await rabbitmqService.disconnect();
         await redisService.disconnect();
         process.exit(0);
      });

   } catch (error) {
      console.error('Failed to start server:', error);
      process.exit(1);
   }
};
