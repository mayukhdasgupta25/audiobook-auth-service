import { Response } from 'express';
import { AuthError, ValidationError } from '../types';
import type { DeviceRequestMeta } from '../types';
import type { Request } from 'express';

export function getDeviceRequestMeta(req: Request): DeviceRequestMeta {
   const userAgent = req.headers?.['user-agent'];
   const ipAddress =
      (typeof req.ip === 'string' && req.ip) ||
      (req.socket?.remoteAddress ?? undefined);

   return {
      ...(userAgent ? { userAgent } : {}),
      ...(ipAddress ? { ipAddress } : {}),
   };
}

export function handleAuthControllerError(res: Response, error: unknown, fallbackMessage: string): void {
   if (error instanceof AuthError) {
      res.status(error.statusCode).json({
         error: error.message,
         code: error.code,
         ...(error.details ? { details: error.details } : {}),
      });
      return;
   }

   if (error instanceof ValidationError) {
      res.status(error.statusCode).json({
         error: error.message,
         code: error.code,
         details: error.details,
      });
      return;
   }

   res.status(401).json({
      error: error instanceof Error ? error.message : fallbackMessage,
   });
}
