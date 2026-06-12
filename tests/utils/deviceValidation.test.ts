import { Role } from '@prisma/client';
import {
   isDeviceOptionalForRegistrationVerifyType,
   resolveDeviceContextForRegistrationVerify,
   validateDeviceContext,
   validateLegacyRegistrationVerifyType,
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

describe('isDeviceOptionalForRegistrationVerifyType (legacy)', () => {
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

describe('validateLegacyRegistrationVerifyType', () => {
   it('allows matching author type for AUTHOR role', () => {
      expect(() =>
         validateLegacyRegistrationVerifyType('author', Role.AUTHOR),
      ).not.toThrow();
   });

   it('rejects author type for LISTENER role', () => {
      expect(() =>
         validateLegacyRegistrationVerifyType('author', Role.LISTENER),
      ).toThrow(ValidationError);
   });

   it('allows organization type for ORG_ADMIN role', () => {
      expect(() =>
         validateLegacyRegistrationVerifyType('organization', Role.ORG_ADMIN),
      ).not.toThrow();
   });
});

describe('resolveDeviceContextForRegistrationVerify', () => {
   it('allows missing device for non-LISTENER roles', () => {
      expect(resolveDeviceContextForRegistrationVerify(undefined, Role.AUTHOR)).toBeUndefined();
      expect(resolveDeviceContextForRegistrationVerify(null, Role.ORG_ADMIN)).toBeUndefined();
      expect(resolveDeviceContextForRegistrationVerify(undefined, Role.ORG_COORDINATOR)).toBeUndefined();
   });

   it('validates device when provided for non-LISTENER roles', () => {
      expect(
         resolveDeviceContextForRegistrationVerify({ deviceId: 'device-1' }, Role.AUTHOR),
      ).toEqual({ deviceId: 'device-1' });
   });

   it('requires device for LISTENER role', () => {
      expect(() => resolveDeviceContextForRegistrationVerify(undefined, Role.LISTENER)).toThrow(ValidationError);
   });
});
