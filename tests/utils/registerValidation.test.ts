import { Role } from '@prisma/client';
import { validateRegisterRequest } from '../../src/utils/registerValidation';
import { ValidationError } from '../../src/types';

const VALID_PASSWORD = 'Password1!';

describe('validateRegisterRequest', () => {
   test('should normalize regular user registration', () => {
      const result = validateRegisterRequest({
         email: 'user@example.com',
         password: VALID_PASSWORD,
         confirmPassword: VALID_PASSWORD,
         address: '456 Oak Ave',
         contact: '9876543210',
      });

      expect(result).toEqual({
         email: 'user@example.com',
         password: VALID_PASSWORD,
         role: Role.LISTENER,
         address: '456 Oak Ave',
         contact: '+919876543210',
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

   test('should validate and normalize author registration from multipart', () => {
      const result = validateRegisterRequest(
         {
            role: Role.AUTHOR,
            email: 'author@example.com',
            password: VALID_PASSWORD,
            confirmPassword: VALID_PASSWORD,
            firstName: 'Jane',
            lastName: 'Doe',
            address: '123 Main St',
            contact: '9876543210',
            profileImage: '/uploads/images/authors/image-1.jpg',
         },
         { isMultipart: true },
      );

      expect(result).toEqual({
         email: 'author@example.com',
         password: VALID_PASSWORD,
         role: Role.AUTHOR,
         firstName: 'Jane',
         lastName: 'Doe',
         address: '123 Main St',
         contact: '+919876543210',
         profileImage: '/uploads/images/authors/image-1.jpg',
      });
   });

   test('should reject staff roles on public registration', () => {
      expect(() =>
         validateRegisterRequest({
            role: Role.GLOBAL_ADMIN,
            email: 'admin@example.com',
            password: VALID_PASSWORD,
            confirmPassword: VALID_PASSWORD,
            address: '123 Main St',
            contact: '9876543210',
         }),
      ).toThrow(ValidationError);
   });

   test('should reject author registration without required fields', () => {
      expect(() =>
         validateRegisterRequest(
            {
               role: Role.AUTHOR,
               email: 'author@example.com',
               password: VALID_PASSWORD,
               confirmPassword: VALID_PASSWORD,
               firstName: 'Jane',
            },
            { isMultipart: true },
         ),
      ).toThrow(ValidationError);
   });

   test('should reject JSON author registration', () => {
      expect(() =>
         validateRegisterRequest({
            role: Role.AUTHOR,
            email: 'author@example.com',
            password: VALID_PASSWORD,
            confirmPassword: VALID_PASSWORD,
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
               password: VALID_PASSWORD,
               confirmPassword: VALID_PASSWORD,
            },
            { isMultipart: true },
         ),
      ).toThrow(ValidationError);
   });

   test('should reject password shorter than 8 characters', () => {
      expect(() =>
         validateRegisterRequest({
            email: 'user@example.com',
            password: 'Pass1!',
            confirmPassword: 'Pass1!',
         }),
      ).toThrow(ValidationError);
   });

   test('should reject password without uppercase letter', () => {
      expect(() =>
         validateRegisterRequest({
            email: 'user@example.com',
            password: 'password1!',
            confirmPassword: 'password1!',
         }),
      ).toThrow(ValidationError);
   });

   test('should reject password without letter or digit', () => {
      expect(() =>
         validateRegisterRequest({
            email: 'user@example.com',
            password: 'PASSWORD!!!',
            confirmPassword: 'PASSWORD!!!',
         }),
      ).toThrow(ValidationError);
   });

   test('should reject password without symbol', () => {
      expect(() =>
         validateRegisterRequest({
            email: 'user@example.com',
            password: 'Password1',
            confirmPassword: 'Password1',
         }),
      ).toThrow(ValidationError);
   });

   test('should reject missing confirmPassword', () => {
      try {
         validateRegisterRequest({
            email: 'user@example.com',
            password: VALID_PASSWORD,
         });
         fail('Expected ValidationError');
      } catch (error) {
         expect(error).toBeInstanceOf(ValidationError);
         expect((error as ValidationError).details['confirmPassword']).toContain('Confirm password is required');
      }
   });

   test('should reject invalid Indian contact for user registration', () => {
      try {
         validateRegisterRequest({
            email: 'user@example.com',
            password: VALID_PASSWORD,
            confirmPassword: VALID_PASSWORD,
            address: '456 Oak Ave',
            contact: '+1-555-0200',
         });
         fail('Expected ValidationError');
      } catch (error) {
         expect(error).toBeInstanceOf(ValidationError);
         expect((error as ValidationError).details['contact']).toContain(
            'Contact must be a valid Indian phone number',
         );
      }
   });

   test('should reject invalid Indian contact for author registration', () => {
      try {
         validateRegisterRequest(
            {
               type: 'AUTHOR',
               email: 'author@example.com',
               password: VALID_PASSWORD,
               confirmPassword: VALID_PASSWORD,
               firstName: 'Jane',
               lastName: 'Doe',
               address: '123 Main St',
               contact: '12345',
            },
            { isMultipart: true },
         );
         fail('Expected ValidationError');
      } catch (error) {
         expect(error).toBeInstanceOf(ValidationError);
         expect((error as ValidationError).details['contact']).toContain(
            'Contact must be a valid Indian phone number',
         );
      }
   });

   test('should reject mismatched confirmPassword', () => {
      try {
         validateRegisterRequest({
            email: 'user@example.com',
            password: VALID_PASSWORD,
            confirmPassword: 'Password2!',
         });
         fail('Expected ValidationError');
      } catch (error) {
         expect(error).toBeInstanceOf(ValidationError);
         expect((error as ValidationError).details['confirmPassword']).toContain(
            'Password and confirm password do not match',
         );
      }
   });
});
