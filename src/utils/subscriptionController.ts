import { Response } from 'express';
import { SubscriptionError } from '../types/subscription';

export function handleSubscriptionError(res: Response, error: unknown): void {
   if (error instanceof SubscriptionError) {
      res.status(error.statusCode).json({ error: error.message, code: error.code });
      return;
   }
   res.status(500).json({ error: 'Internal server error', code: 'INTERNAL_ERROR' });
}

export interface PaginationMeta {
   page: number;
   limit: number;
   totalCount: number;
   totalPages: number;
   hasNextPage: boolean;
   hasPrevPage: boolean;
}

export function calculatePagination(page: number, limit: number, totalCount: number): PaginationMeta {
   const totalPages = Math.ceil(totalCount / limit) || 1;
   return {
      page,
      limit,
      totalCount,
      totalPages,
      hasNextPage: page < totalPages,
      hasPrevPage: page > 1,
   };
}
