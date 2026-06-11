import { ValidationError } from '../types';
import type { DeviceContext } from '../types';
import { DEVICE_OPTIONAL_VERIFY_OTP_TYPES } from '../constants/registrationVerifyType';

const DEVICE_ID_MAX_LENGTH = 128;

export function isDeviceOptionalForRegistrationVerifyType(type: unknown): boolean {
   if (typeof type !== 'string') {
      return false;
   }

   return DEVICE_OPTIONAL_VERIFY_OTP_TYPES.has(type.trim().toLowerCase());
}

export function resolveDeviceContextForRegistrationVerify(
   device: unknown,
   type: unknown,
): DeviceContext | undefined {
   if (isDeviceOptionalForRegistrationVerifyType(type)) {
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
