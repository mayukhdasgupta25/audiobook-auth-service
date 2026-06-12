export class DomainError extends Error {
   statusCode: number;
   code: string;

   constructor(message: string, statusCode: number = 400, code: string = 'DOMAIN_ERROR') {
      super(message);
      this.statusCode = statusCode;
      this.code = code;
      this.name = 'DomainError';
   }

   static notFound(message: string): DomainError {
      return new DomainError(message, 404, 'NOT_FOUND');
   }

   static conflict(message: string): DomainError {
      return new DomainError(message, 409, 'CONFLICT');
   }

   static validation(message: string): DomainError {
      return new DomainError(message, 400, 'VALIDATION_ERROR');
   }

   static forbidden(message: string): DomainError {
      return new DomainError(message, 403, 'FORBIDDEN');
   }

   static internal(message: string): DomainError {
      return new DomainError(message, 500, 'INTERNAL_ERROR');
   }
}

export interface AuthenticatedRequest {
   user?: {
      id: string;
      email: string;
      role: string;
   };
   token?: string;
}
