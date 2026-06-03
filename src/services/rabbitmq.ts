import amqp from 'amqplib';
import { config } from '../config/env';
import { rabbitmqLogger } from '../utils/logger';

/**
 * RabbitMQ service for publishing events
 */
export class RabbitMQService {
   private connection: any = null;
   private channel: any = null;
   private isConnected: boolean = false;

   constructor() {
      // Constructor is empty - initialization happens in connect()
   }

   /**
    * Connect to RabbitMQ and set up exchange
    */
   async connect(): Promise<void> {
      try {
         if (config.NODE_ENV !== 'test') {
            rabbitmqLogger.info('Connecting to RabbitMQ...');
         }

         // Connect to RabbitMQ
         this.connection = await amqp.connect(config.RABBITMQ_URL);
         if (config.NODE_ENV !== 'test') {
            rabbitmqLogger.info('Connected to RabbitMQ');
         }

         // Create channel
         this.channel = await this.connection.createChannel();
         if (config.NODE_ENV !== 'test') {
            rabbitmqLogger.info('Created RabbitMQ channel');
         }

         // Set up exchange (topic exchange for routing)
         await this.channel.assertExchange(config.RABBITMQ_EXCHANGE, 'topic', {
            durable: true, // Exchange survives broker restarts
         });
         if (config.NODE_ENV !== 'test') {
            rabbitmqLogger.info({ exchange: config.RABBITMQ_EXCHANGE }, 'Exchange asserted');
         }

         this.isConnected = true;

         // Handle connection close
         this.connection.on('close', () => {
            if (config.NODE_ENV !== 'test') {
               rabbitmqLogger.info('RabbitMQ connection closed');
            }
            this.isConnected = false;
         });

         this.connection.on('error', (err: unknown) => {
            if (config.NODE_ENV !== 'test') {
               rabbitmqLogger.error({ err }, 'RabbitMQ connection error');
            }
            this.isConnected = false;
         });

      } catch (error) {
         if (config.NODE_ENV !== 'test') {
            rabbitmqLogger.error({ err: error }, 'Failed to connect to RabbitMQ');
         }
         this.isConnected = false;
         throw error;
      }
   }

   /**
    * Disconnect from RabbitMQ
    */
   async disconnect(): Promise<void> {
      try {
         if (this.channel) {
            await this.channel.close();
            this.channel = null;
         }

         if (this.connection) {
            await this.connection.close();
            this.connection = null;
         }

         this.isConnected = false;
         if (config.NODE_ENV !== 'test') {
            rabbitmqLogger.info('Disconnected from RabbitMQ');
         }
      } catch (error) {
         if (config.NODE_ENV !== 'test') {
            rabbitmqLogger.error({ err: error }, 'Error disconnecting from RabbitMQ');
         }
      }
   }

   /**
    * Check if service is connected
    */
   isServiceConnected(): boolean {
      return this.isConnected && this.connection !== null && this.channel !== null;
   }

   /**
    * Health check — verifies the exchange is reachable on the open channel
    */
   async healthCheck(): Promise<boolean> {
      if (!this.isServiceConnected()) {
         return false;
      }

      try {
         await this.channel.checkExchange(config.RABBITMQ_EXCHANGE);
         return true;
      } catch {
         return false;
      }
   }

   /**
    * Publish user created event
    */
   async publishUserCreated(userId: string, firstName?: string, lastName?: string): Promise<void> {
      if (!this.isServiceConnected()) {
         throw new Error('RabbitMQ service is not connected');
      }

      try {
         // Build message object, only including firstName and lastName if provided
         const messageData: { userId: string; firstName?: string; lastName?: string } = { userId };
         if (firstName !== undefined) {
            messageData.firstName = firstName;
         }
         if (lastName !== undefined) {
            messageData.lastName = lastName;
         }
         const message = JSON.stringify(messageData);
         const routingKey = 'user.created';

         const published = this.channel!.publish(
            config.RABBITMQ_EXCHANGE,
            routingKey,
            Buffer.from(message),
            {
               persistent: true, // Message survives broker restarts
               timestamp: Date.now(),
            }
         );

         if (!published) {
            throw new Error('Failed to publish message to RabbitMQ');
         }

         if (config.NODE_ENV !== 'test') {
            rabbitmqLogger.info({ userId, routingKey }, 'Published user.created event');
         }
      } catch (error) {
         if (config.NODE_ENV !== 'test') {
            rabbitmqLogger.error({ err: error, userId }, 'Error publishing user created event');
         }
         throw error;
      }
   }

   /**
    * Publish generic event (for future extensibility)
    */
   async publishEvent(routingKey: string, data: any): Promise<void> {
      if (!this.isServiceConnected()) {
         throw new Error('RabbitMQ service is not connected');
      }

      try {
         const message = JSON.stringify(data);

         const published = this.channel!.publish(
            config.RABBITMQ_EXCHANGE,
            routingKey,
            Buffer.from(message),
            {
               persistent: true,
               timestamp: Date.now(),
            }
         );

         if (!published) {
            throw new Error('Failed to publish message to RabbitMQ');
         }

         if (config.NODE_ENV !== 'test') {
            rabbitmqLogger.info({ routingKey }, 'Published event');
         }
      } catch (error) {
         if (config.NODE_ENV !== 'test') {
            rabbitmqLogger.error({ err: error, routingKey }, 'Error publishing event');
         }
         throw error;
      }
   }
}

// Export singleton instance
export const rabbitmqService = new RabbitMQService();
