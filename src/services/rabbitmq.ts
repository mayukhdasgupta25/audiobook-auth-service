import amqp from 'amqplib';
import { config } from '../config/env';

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
         console.log('Connecting to RabbitMQ...');

         // Connect to RabbitMQ
         this.connection = await amqp.connect(config.RABBITMQ_URL);
         console.log('Connected to RabbitMQ');

         // Create channel
         this.channel = await this.connection.createChannel();
         console.log('Created RabbitMQ channel');

         // Set up exchange (topic exchange for routing)
         await this.channel.assertExchange(config.RABBITMQ_EXCHANGE, 'topic', {
            durable: true, // Exchange survives broker restarts
         });
         console.log(`Exchange '${config.RABBITMQ_EXCHANGE}' asserted`);

         this.isConnected = true;

         // Handle connection close
         this.connection.on('close', () => {
            console.log('RabbitMQ connection closed');
            this.isConnected = false;
         });

         this.connection.on('error', (err: any) => {
            console.error('RabbitMQ connection error:', err);
            this.isConnected = false;
         });

      } catch (error) {
         console.error('Failed to connect to RabbitMQ:', error);
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
         console.log('Disconnected from RabbitMQ');
      } catch (error) {
         console.error('Error disconnecting from RabbitMQ:', error);
      }
   }

   /**
    * Check if service is connected
    */
   isServiceConnected(): boolean {
      return this.isConnected && this.connection !== null && this.channel !== null;
   }

   /**
    * Publish user created event
    */
   async publishUserCreated(userId: string): Promise<void> {
      if (!this.isServiceConnected()) {
         throw new Error('RabbitMQ service is not connected');
      }

      try {
         const message = JSON.stringify({ userId });
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

         console.log(`Published user.created event for user ${userId}`);
      } catch (error) {
         console.error('Error publishing user created event:', error);
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

         console.log(`Published event '${routingKey}'`);
      } catch (error) {
         console.error(`Error publishing event '${routingKey}':`, error);
         throw error;
      }
   }
}

// Export singleton instance
export const rabbitmqService = new RabbitMQService();
