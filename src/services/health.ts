import { PrismaClient } from '@prisma/client';
import { rabbitmqService } from './rabbitmq';
import { redisService } from './redis';

const prisma = new PrismaClient();

export type DependencyHealth = {
   database: boolean;
   redis: boolean;
   rabbitmq: boolean;
};

export async function getDependencyHealth(): Promise<DependencyHealth> {
   const [database, redis, rabbitmq] = await Promise.all([
      checkDatabaseHealth(),
      redisService.healthCheck(),
      rabbitmqService.healthCheck(),
   ]);

   return { database, redis, rabbitmq };
}

async function checkDatabaseHealth(): Promise<boolean> {
   try {
      await prisma.$queryRaw`SELECT 1`;
      return true;
   } catch {
      return false;
   }
}

export function isDependencyHealthOk(checks: DependencyHealth): boolean {
   return checks.database && checks.redis && checks.rabbitmq;
}
