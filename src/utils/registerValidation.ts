import { Role } from '@prisma/client';
import { RegisterRequest, ValidationError } from '../types';

export function validateRegisterRequest(body: RegisterRequest): RegisterRequest {
   const {
      email,
      password,
      type = 'USER',
      firstName,
      lastName,
      address,
      contact,
      avatar,
      profileImage,
   } = body;

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

      const normalized: RegisterRequest = {
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

      if (profileImage !== undefined && profileImage !== null && String(profileImage).trim().length > 0) {
         normalized.profileImage = String(profileImage).trim();
      }

      return normalized;
   }

   const userDetails: Record<string, string[]> = {};

   if (!address || typeof address !== 'string' || address.trim().length === 0) {
      userDetails['address'] = ['Address is required for user registration'];
   }

   if (!contact || typeof contact !== 'string' || contact.trim().length === 0) {
      userDetails['contact'] = ['Contact is required for user registration'];
   }

   if (Object.keys(userDetails).length > 0) {
      throw new ValidationError('User registration requires additional fields', userDetails);
   }

   const normalizedUser: RegisterRequest = {
      email,
      password,
      role: body.role ?? Role.USER,
      type: 'USER',
      address: address!.trim(),
      contact: contact!.trim(),
   };

   if (firstName !== undefined && firstName !== null && String(firstName).trim().length > 0) {
      normalizedUser.firstName = String(firstName).trim();
   }
   if (lastName !== undefined && lastName !== null && String(lastName).trim().length > 0) {
      normalizedUser.lastName = String(lastName).trim();
   }
   if (avatar !== undefined && avatar !== null && String(avatar).trim().length > 0) {
      normalizedUser.avatar = String(avatar).trim();
   }

   return normalizedUser;
}
