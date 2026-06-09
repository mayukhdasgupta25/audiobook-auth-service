import {
   isDeviceOptionalForRegistrationVerifyType,
   resolveDeviceContextForRegistrationVerify,
   validateDeviceContext,
} from '../../src/utils/deviceValidation';
import { ValidationError } from '../../src/types';

describe('validateDeviceContext', () => {
   it('returns trimmed device context', () => {
      expect(
         validateDeviceContext({
            deviceId: '  abc-123  ',
            deviceName: ' Phone ',
            platform: 'ios',
         }),
      ).toEqual({
         deviceId: 'abc-123',
         deviceName: 'Phone',
         platform: 'ios',
      });
   });

   it('throws when deviceId is missing', () => {
      expect(() => validateDeviceContext({})).toThrow(ValidationError);
      try {
         validateDeviceContext({});
      } catch (error) {
         expect(error).toMatchObject({ code: 'DEVICE_ID_REQUIRED', statusCode: 400 });
      }
   });
});

describe('isDeviceOptionalForRegistrationVerifyType', () => {
   it('returns true for author and organization', () => {
      expect(isDeviceOptionalForRegistrationVerifyType('author')).toBe(true);
      expect(isDeviceOptionalForRegistrationVerifyType('AUTHOR')).toBe(true);
      expect(isDeviceOptionalForRegistrationVerifyType('organization')).toBe(true);
      expect(isDeviceOptionalForRegistrationVerifyType(' Organization ')).toBe(true);
   });

   it('returns false for other or missing types', () => {
      expect(isDeviceOptionalForRegistrationVerifyType('user')).toBe(false);
      expect(isDeviceOptionalForRegistrationVerifyType(undefined)).toBe(false);
      expect(isDeviceOptionalForRegistrationVerifyType(null)).toBe(false);
   });
});

describe('resolveDeviceContextForRegistrationVerify', () => {
   it('allows missing device for author and organization', () => {
      expect(resolveDeviceContextForRegistrationVerify(undefined, 'author')).toBeUndefined();
      expect(resolveDeviceContextForRegistrationVerify(null, 'organization')).toBeUndefined();
   });

   it('validates device when provided for author and organization', () => {
      expect(
         resolveDeviceContextForRegistrationVerify({ deviceId: 'device-1' }, 'author'),
      ).toEqual({ deviceId: 'device-1' });
   });

   it('requires device for other types', () => {
      expect(() => resolveDeviceContextForRegistrationVerify(undefined, 'user')).toThrow(ValidationError);
      expect(() => resolveDeviceContextForRegistrationVerify(undefined, undefined)).toThrow(ValidationError);
   });
});
