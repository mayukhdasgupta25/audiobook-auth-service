import { Role } from '@prisma/client';

export class SubscriptionError extends Error {
   statusCode: number;
   code: string;

   constructor(message: string, statusCode: number = 400, code: string = 'SUBSCRIPTION_ERROR') {
      super(message);
      this.statusCode = statusCode;
      this.code = code;
      this.name = 'SubscriptionError';
   }

   static notFound(message: string): SubscriptionError {
      return new SubscriptionError(message, 404, 'NOT_FOUND');
   }

   static conflict(message: string): SubscriptionError {
      return new SubscriptionError(message, 409, 'CONFLICT');
   }

   static validation(message: string): SubscriptionError {
      return new SubscriptionError(message, 400, 'VALIDATION_ERROR');
   }

   static unauthorized(message: string): SubscriptionError {
      return new SubscriptionError(message, 401, 'UNAUTHORIZED');
   }

   static forbidden(message: string): SubscriptionError {
      return new SubscriptionError(message, 403, 'FORBIDDEN');
   }

   static internal(message: string): SubscriptionError {
      return new SubscriptionError(message, 500, 'INTERNAL_ERROR');
   }
}

export interface AuthUserPayload {
   id: string;
   email: string;
   role: Role;
}

export interface AuthenticatedSubscriptionRequest {
   user?: AuthUserPayload;
   token?: string;
}
