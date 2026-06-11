import {
   AuthRole,
   isGlobalAdminRole,
   normalizeAuthRole,
} from '../../src/constants/authRoles';
import { ClientType } from '../../src/constants/clientType';
import { RegisterAccountType } from '../../src/constants/registerAccountType';
import { RegistrationVerifyType } from '../../src/constants/registrationVerifyType';

describe('authRoles', () => {
   describe('normalizeAuthRole', () => {
      test('normalizes role case-insensitively', () => {
         expect(normalizeAuthRole('ADMIN')).toBe('admin');
         expect(normalizeAuthRole(' admin ')).toBe('admin');
         expect(normalizeAuthRole(undefined)).toBe('');
      });
   });

   describe('isGlobalAdminRole', () => {
      test('returns true for ADMIN and admin', () => {
         expect(isGlobalAdminRole(AuthRole.ADMIN)).toBe(true);
         expect(isGlobalAdminRole('admin')).toBe(true);
      });

      test('returns false for USER and AUTHOR', () => {
         expect(isGlobalAdminRole(AuthRole.USER)).toBe(false);
         expect(isGlobalAdminRole(AuthRole.AUTHOR)).toBe(false);
      });
   });
});

describe('domain constants', () => {
   test('RegisterAccountType values match registration API', () => {
      expect(RegisterAccountType.USER).toBe('USER');
      expect(RegisterAccountType.AUTHOR).toBe('AUTHOR');
   });

   test('ClientType values match auth client payloads', () => {
      expect(ClientType.BROWSER).toBe('browser');
      expect(ClientType.MOBILE).toBe('mobile');
   });

   test('RegistrationVerifyType values are lowercase', () => {
      expect(RegistrationVerifyType.ORGANIZATION).toBe('organization');
      expect(RegistrationVerifyType.AUTHOR).toBe('author');
   });
});
