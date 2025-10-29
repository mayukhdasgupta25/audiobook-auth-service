import { RabbitMQService } from '../../src/services/rabbitmq';
import { config } from '../../src/config/env';

// Create mocks inside factory to avoid hoisting issues
jest.mock('amqplib', () => {
   const mockChannel = {
      assertExchange: jest.fn().mockResolvedValue(undefined),
      publish: jest.fn().mockReturnValue(true),
      close: jest.fn().mockResolvedValue(undefined),
   };

   const mockConnection = {
      createChannel: jest.fn().mockResolvedValue(mockChannel),
      close: jest.fn().mockResolvedValue(undefined),
      on: jest.fn(),
   };

   return {
      __esModule: true,
      default: {
         connect: jest.fn().mockResolvedValue(mockConnection),
      },
   };
});

describe('RabbitMQService', () => {
   let rabbitmqService: RabbitMQService;

   beforeEach(() => {
      jest.clearAllMocks();
      rabbitmqService = new RabbitMQService();
      (rabbitmqService as any).isConnected = false;
      (rabbitmqService as any).connection = null;
      (rabbitmqService as any).channel = null;
   });

   describe('Connection Management', () => {
      test('should connect to RabbitMQ successfully', async () => {
         const amqp = await import('amqplib');

         await rabbitmqService.connect();

         expect(amqp.default.connect).toHaveBeenCalled();
      });

      test('should handle connection errors', async () => {
         const amqp = await import('amqplib');
         const error = new Error('Connection failed');
         (amqp as any).default.connect.mockRejectedValueOnce(error);

         await expect(rabbitmqService.connect()).rejects.toThrow();
      });

      test('should disconnect from RabbitMQ', async () => {
         const mockChannel = {
            assertExchange: jest.fn().mockResolvedValue(undefined),
            publish: jest.fn().mockReturnValue(true),
            close: jest.fn().mockResolvedValue(undefined),
         };

         const mockConnection = {
            createChannel: jest.fn().mockResolvedValue(mockChannel),
            close: jest.fn().mockResolvedValue(undefined),
            on: jest.fn(),
         };

         (rabbitmqService as any).channel = mockChannel;
         (rabbitmqService as any).connection = mockConnection;
         (rabbitmqService as any).isConnected = true;

         await rabbitmqService.disconnect();

         expect(mockChannel.close).toHaveBeenCalledTimes(1);
         expect(mockConnection.close).toHaveBeenCalledTimes(1);
      });

      test('should handle disconnect when not connected', async () => {
         await rabbitmqService.disconnect();

         // Should not throw
         expect(true).toBe(true);
      });

      test('should check if service is connected', () => {
         const mockChannel = {
            close: jest.fn(),
         };

         const mockConnection = {
            close: jest.fn(),
         };

         (rabbitmqService as any).isConnected = true;
         (rabbitmqService as any).connection = mockConnection;
         (rabbitmqService as any).channel = mockChannel;

         const result = rabbitmqService.isServiceConnected();

         expect(result).toBe(true);
      });

      test('should return false if not connected', () => {
         (rabbitmqService as any).isConnected = false;

         const result = rabbitmqService.isServiceConnected();

         expect(result).toBe(false);
      });
   });

   describe('Publishing Events', () => {
      let mockChannel: any;
      let mockConnection: any;

      beforeEach(() => {
         mockChannel = {
            assertExchange: jest.fn().mockResolvedValue(undefined),
            publish: jest.fn().mockReturnValue(true),
            close: jest.fn().mockResolvedValue(undefined),
         };

         mockConnection = {
            createChannel: jest.fn().mockResolvedValue(mockChannel),
            close: jest.fn().mockResolvedValue(undefined),
            on: jest.fn(),
         };

         (rabbitmqService as any).connection = mockConnection;
         (rabbitmqService as any).channel = mockChannel;
         (rabbitmqService as any).isConnected = true;
      });

      test('should publish user created event', async () => {
         const userId = 'user-123';
         mockChannel.publish.mockReturnValueOnce(true);

         await rabbitmqService.publishUserCreated(userId);

         expect(mockChannel.publish).toHaveBeenCalledWith(
            config.RABBITMQ_EXCHANGE,
            'user.created',
            Buffer.from(JSON.stringify({ userId })),
            expect.objectContaining({
               persistent: true,
               timestamp: expect.any(Number),
            })
         );
      });

      test('should publish generic event', async () => {
         const routingKey = 'user.updated';
         const data = { userId: 'user-456', action: 'update' };
         mockChannel.publish.mockReturnValueOnce(true);

         await rabbitmqService.publishEvent(routingKey, data);

         expect(mockChannel.publish).toHaveBeenCalledWith(
            config.RABBITMQ_EXCHANGE,
            routingKey,
            Buffer.from(JSON.stringify(data)),
            expect.objectContaining({
               persistent: true,
               timestamp: expect.any(Number),
            })
         );
      });

      test('should throw error if publish fails', async () => {
         const userId = 'user-123';
         mockChannel.publish.mockReturnValueOnce(false);

         await expect(rabbitmqService.publishUserCreated(userId)).rejects.toThrow(
            'Failed to publish message to RabbitMQ'
         );
      });

      test('should throw error if not connected when publishing', async () => {
         (rabbitmqService as any).isConnected = false;

         await expect(rabbitmqService.publishUserCreated('user-123')).rejects.toThrow(
            'RabbitMQ service is not connected'
         );
      });
   });
});
