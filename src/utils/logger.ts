import path from 'path';
import pino, { Logger, multistream } from 'pino';
import pretty from 'pino-pretty';
import { config } from '../config/env';

const LOG_DIR = 'logs';

type ServiceName = 'app' | 'rabbitmq' | 'redis' | 'email';

const SERVICE_LOG_FILES: Record<ServiceName, string> = {
   app: 'app.log',
   rabbitmq: 'rabbitmq.log',
   redis: 'redis.log',
   email: 'email.log',
};

function createServiceLogger(service: ServiceName): Logger {
   if (config.NODE_ENV === 'test') {
      return pino({ level: 'silent' });
   }

   const logPath = path.join(process.cwd(), LOG_DIR, SERVICE_LOG_FILES[service]);
   const fileStream = pino.destination({
      dest: logPath,
      append: true,
      mkdir: true,
      sync: false,
   });

   const loggerOptions = {
      level: config.LOG_LEVEL,
      base: { service },
   };

   const usePrettyConsole =
      config.NODE_ENV === 'development' || config.NODE_ENV === 'testing';

   if (usePrettyConsole) {
      const prettyStream = pretty({
         colorize: true,
         translateTime: 'SYS:standard',
         ignore: 'pid,hostname,service',
      });

      return pino(
         loggerOptions,
         multistream([
            { stream: fileStream },
            { stream: prettyStream },
         ])
      );
   }

   return pino(loggerOptions, fileStream);
}

export const appLogger = createServiceLogger('app');
export const rabbitmqLogger = createServiceLogger('rabbitmq');
export const redisLogger = createServiceLogger('redis');
export const emailLogger = createServiceLogger('email');
