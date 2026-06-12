import { Role } from '@prisma/client';
import { ValidationError } from '../types';
import type { DeviceContext } from '../types';
import {
   isDeviceOptionalForRole,
} from '../constants/authRoles';
import { RegistrationVerifyType } from '../constants/registrationVerifyType';

const DEVICE_ID_MAX_LENGTH = 128;

/** @deprecated Use isDeviceOptionalForRole(user.role) instead */
export function isDeviceOptionalForRegistrationVerifyType(type: unknown): boolean {
   if (typeof type !== 'string') {
      return false;
   }

   const normalized = type.trim().toLowerCase();
   return (
      normalized === RegistrationVerifyType.AUTHOR ||
      normalized === RegistrationVerifyType.ORGANIZATION
   );
}

/**
 * Validate legacy `type` param against the registered user's role when provided.
 */
export function validateLegacyRegistrationVerifyType(
   type: unknown,
   userRole: Role,
): void {
   if (type === undefined || type === null || type === '') {
      return;
   }

   if (typeof type !== 'string') {
      throw new ValidationError('Invalid type', { type: ['type must be a string'] }, 400);
   }

   const normalized = type.trim().toLowerCase();

   if (normalized === RegistrationVerifyType.AUTHOR && userRole !== Role.AUTHOR) {
      throw new ValidationError(
         'type does not match registered role',
         { type: ['type "author" is only valid for AUTHOR registrations'] },
         400,
      );
   }

   if (
      normalized === RegistrationVerifyType.ORGANIZATION &&
      userRole !== Role.ORG_ADMIN &&
      userRole !== Role.ORG_COORDINATOR
   ) {
      throw new ValidationError(
         'type does not match registered role',
         { type: ['type "organization" is only valid for ORG_ADMIN or ORG_COORDINATOR registrations'] },
         400,
      );
   }

   if (
      normalized !== RegistrationVerifyType.AUTHOR &&
      normalized !== RegistrationVerifyType.ORGANIZATION &&
      userRole === Role.LISTENER
   ) {
      // Allow omitted/legacy values for listeners; reject unknown types for non-listeners
      if (normalized !== 'user' && normalized !== 'listener') {
         throw new ValidationError(
            'Invalid type',
            { type: ['type must be "author" or "organization" when provided'] },
            400,
         );
      }
   }
}

export function resolveDeviceContextForRegistrationVerify(
   device: unknown,
   userRole: Role,
): DeviceContext | undefined {
   if (isDeviceOptionalForRole(userRole)) {
      if (device === undefined || device === null) {
         return undefined;
      }
      return validateDeviceContext(device);
   }

   return validateDeviceContext(device);
}

export function validateDeviceContext(device: unknown): DeviceContext {
   if (!device || typeof device !== 'object' || Array.isArray(device)) {
      throw new ValidationError(
         'Device information is required',
         { device: ['device object with deviceId is required'] },
         400,
         'DEVICE_ID_REQUIRED',
      );
   }

   const record = device as Record<string, unknown>;
   const rawDeviceId = record['deviceId'];

   if (typeof rawDeviceId !== 'string') {
      throw new ValidationError(
         'deviceId is required',
         { 'device.deviceId': ['deviceId must be a non-empty string'] },
         400,
         'DEVICE_ID_REQUIRED',
      );
   }

   const deviceId = rawDeviceId.trim();
   if (deviceId.length === 0 || deviceId.length > DEVICE_ID_MAX_LENGTH) {
      throw new ValidationError(
         'deviceId must be between 1 and 128 characters',
         { 'device.deviceId': ['invalid deviceId length'] },
         400,
         'DEVICE_ID_REQUIRED',
      );
   }

   const result: DeviceContext = { deviceId };

   if (record['deviceName'] !== undefined) {
      if (typeof record['deviceName'] !== 'string') {
         throw new ValidationError('deviceName must be a string', {}, 400, 'VALIDATION_ERROR');
      }
      const deviceName = record['deviceName'].trim();
      if (deviceName.length > 0) {
         result.deviceName = deviceName.slice(0, 128);
      }
   }

   if (record['platform'] !== undefined) {
      if (typeof record['platform'] !== 'string') {
         throw new ValidationError('platform must be a string', {}, 400, 'VALIDATION_ERROR');
      }
      const platform = record['platform'].trim();
      if (platform.length > 0) {
         result.platform = platform.slice(0, 64);
      }
   }

   return result;
}
