import { Role } from '@prisma/client';
import { validateRegisterRequest } from '../../src/utils/registerValidation';
import { ValidationError } from '../../src/types';

describe('validateRegisterRequest', () => {
   test('should normalize regular user registration', () => {
      const result = validateRegisterRequest({
         email: 'user@example.com',
         password: 'password123',
         address: '456 Oak Ave',
         contact: '+1-555-0200',
      });

      expect(result).toEqual({
         email: 'user@example.com',
         password: 'password123',
         role: Role.USER,
         type: 'USER',
         address: '456 Oak Ave',
         contact: '+1-555-0200',
      });
   });

   test('should reject user registration without address and contact', () => {
      expect(() =>
         validateRegisterRequest({
            email: 'user@example.com',
            password: 'password123',
         }),
      ).toThrow(ValidationError);
   });

   test('should validate and normalize author registration', () => {
      const result = validateRegisterRequest({
         type: 'AUTHOR',
         email: 'author@example.com',
         password: 'password123',
         firstName: 'Jane',
         lastName: 'Doe',
         address: '123 Main St',
         contact: '+1-555-0100',
      });

      expect(result).toEqual({
         email: 'author@example.com',
         password: 'password123',
         role: Role.AUTHOR,
         type: 'AUTHOR',
         firstName: 'Jane',
         lastName: 'Doe',
         address: '123 Main St',
         contact: '+1-555-0100',
      });
   });

   test('should force AUTHOR role for author registration', () => {
      const result = validateRegisterRequest({
         type: 'AUTHOR',
         email: 'author@example.com',
         password: 'password123',
         role: Role.ADMIN,
         firstName: 'Jane',
         lastName: 'Doe',
         address: '123 Main St',
      });

      expect(result.role).toBe(Role.AUTHOR);
   });

   test('should reject author registration without required fields', () => {
      expect(() =>
         validateRegisterRequest({
            type: 'AUTHOR',
            email: 'author@example.com',
            password: 'password123',
            firstName: 'Jane',
         }),
      ).toThrow(ValidationError);
   });
});
