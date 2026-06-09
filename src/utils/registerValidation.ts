import { Role } from '@prisma/client';
import { RegisterRequest, ValidationError } from '../types';

export function validateRegisterRequest(body: RegisterRequest): RegisterRequest {
   const { email, password, type = 'USER', firstName, lastName, address, contact } = body;

   if (!email || typeof email !== 'string') {
      throw new ValidationError('Email is required', { email: ['Email is required'] });
   }

   if (!password || typeof password !== 'string') {
      throw new ValidationError('Password is required', { password: ['Password is required'] });
   }

   if (type !== 'USER' && type !== 'AUTHOR') {
      throw new ValidationError('Invalid user type', { type: ['Type must be USER or AUTHOR'] });
   }

   if (type === 'AUTHOR') {
      const details: Record<string, string[]> = {};

      if (!firstName || typeof firstName !== 'string' || firstName.trim().length === 0) {
         details['firstName'] = ['First name is required for author registration'];
      }

      if (!lastName || typeof lastName !== 'string' || lastName.trim().length === 0) {
         details['lastName'] = ['Last name is required for author registration'];
      }

      if (!address || typeof address !== 'string' || address.trim().length === 0) {
         details['address'] = ['Address is required for author registration'];
      }

      if (Object.keys(details).length > 0) {
         throw new ValidationError('Author registration requires additional fields', details);
      }

      return {
         email,
         password,
         role: Role.AUTHOR,
         type: 'AUTHOR',
         firstName: firstName!.trim(),
         lastName: lastName!.trim(),
         address: address!.trim(),
         ...(contact !== undefined && contact !== null && String(contact).trim().length > 0
            ? { contact: String(contact).trim() }
            : {}),
      };
   }

   return {
      email,
      password,
      role: body.role ?? Role.USER,
      type: 'USER',
   };
}
