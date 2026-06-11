export const RegisterAccountType = {
   USER: 'USER',
   AUTHOR: 'AUTHOR',
} as const;

export type RegisterAccountTypeValue =
   (typeof RegisterAccountType)[keyof typeof RegisterAccountType];

export const RegisterAccountTypeValues = Object.values(RegisterAccountType);
