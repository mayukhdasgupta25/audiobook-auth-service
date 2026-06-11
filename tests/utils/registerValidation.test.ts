import { Role } from '@prisma/client';
import { validateRegisterRequest } from '../../src/utils/registerValidation';
import { ValidationError } from '../../src/types';

describe('validateRegisterRequest', () => {
   test('should normalize regular user registration', () => {
      const result = validateRegisterRequest({
         email: 'user@example.com',
         password: 'password123',
      });

      expect(result).toEqual({
         email: 'user@example.com',
         password: 'password123',
         role: Role.USER,
         type: 'USER',
      });
   });

   test('should validate and normalize author registration from multipart', () => {
      const result = validateRegisterRequest(
         {
            type: 'AUTHOR',
            email: 'author@example.com',
            password: 'password123',
            firstName: 'Jane',
            lastName: 'Doe',
            address: '123 Main St',
            contact: '+1-555-0100',
            profileImage: '/uploads/images/authors/image-1.jpg',
         },
         { isMultipart: true },
      );

      expect(result).toEqual({
         email: 'author@example.com',
         password: 'password123',
         role: Role.AUTHOR,
         type: 'AUTHOR',
         firstName: 'Jane',
         lastName: 'Doe',
         address: '123 Main St',
         contact: '+1-555-0100',
         profileImage: '/uploads/images/authors/image-1.jpg',
      });
   });

   test('should force AUTHOR role for author registration', () => {
      const result = validateRegisterRequest(
         {
            type: 'AUTHOR',
            email: 'author@example.com',
            password: 'password123',
            role: Role.ADMIN,
            firstName: 'Jane',
            lastName: 'Doe',
            address: '123 Main St',
         },
         { isMultipart: true },
      );

      expect(result.role).toBe(Role.AUTHOR);
   });

   test('should reject author registration without required fields', () => {
      expect(() =>
         validateRegisterRequest(
            {
               type: 'AUTHOR',
               email: 'author@example.com',
               password: 'password123',
               firstName: 'Jane',
            },
            { isMultipart: true },
         ),
      ).toThrow(ValidationError);
   });

   test('should reject JSON author registration', () => {
      expect(() =>
         validateRegisterRequest({
            type: 'AUTHOR',
            email: 'author@example.com',
            password: 'password123',
            firstName: 'Jane',
            lastName: 'Doe',
            address: '123 Main St',
         }),
      ).toThrow(ValidationError);
   });

   test('should reject multipart user registration', () => {
      expect(() =>
         validateRegisterRequest(
            {
               email: 'user@example.com',
               password: 'password123',
            },
            { isMultipart: true },
         ),
      ).toThrow(ValidationError);
   });
});
