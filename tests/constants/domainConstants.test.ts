import {
   AuthRole,
   isGlobalAdminRole,
   isOrgAdminRole,
   isOrgCoordinatorRole,
   normalizeAuthRole,
} from '../../src/constants/authRoles';
import { ClientType } from '../../src/constants/clientType';
import { RegistrationVerifyType } from '../../src/constants/registrationVerifyType';

describe('authRoles', () => {
   describe('normalizeAuthRole', () => {
      test('normalizes role case-insensitively', () => {
         expect(normalizeAuthRole('GLOBAL_ADMIN')).toBe('global_admin');
         expect(normalizeAuthRole(' global_admin ')).toBe('global_admin');
         expect(normalizeAuthRole(undefined)).toBe('');
      });
   });

   describe('isGlobalAdminRole', () => {
      test('returns true for GLOBAL_ADMIN and global_admin', () => {
         expect(isGlobalAdminRole(AuthRole.GLOBAL_ADMIN)).toBe(true);
         expect(isGlobalAdminRole('global_admin')).toBe(true);
      });

      test('returns false for LISTENER, ORG_ADMIN, and AUTHOR', () => {
         expect(isGlobalAdminRole(AuthRole.LISTENER)).toBe(false);
         expect(isGlobalAdminRole(AuthRole.ORG_ADMIN)).toBe(false);
         expect(isGlobalAdminRole(AuthRole.AUTHOR)).toBe(false);
      });
   });

   describe('org staff role helpers', () => {
      test('isOrgAdminRole matches ORG_ADMIN only', () => {
         expect(isOrgAdminRole(AuthRole.ORG_ADMIN)).toBe(true);
         expect(isOrgAdminRole(AuthRole.ORG_COORDINATOR)).toBe(false);
      });

      test('isOrgCoordinatorRole matches ORG_COORDINATOR only', () => {
         expect(isOrgCoordinatorRole(AuthRole.ORG_COORDINATOR)).toBe(true);
         expect(isOrgCoordinatorRole(AuthRole.ORG_ADMIN)).toBe(false);
      });
   });
});

describe('domain constants', () => {
   test('AuthRole public registration values', () => {
      expect(AuthRole.LISTENER).toBe('LISTENER');
      expect(AuthRole.AUTHOR).toBe('AUTHOR');
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
