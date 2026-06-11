export const RegistrationVerifyType = {
   ORGANIZATION: 'organization',
   AUTHOR: 'author',
} as const;

export type RegistrationVerifyTypeValue =
   (typeof RegistrationVerifyType)[keyof typeof RegistrationVerifyType];

export const DEVICE_OPTIONAL_VERIFY_OTP_TYPES = new Set<string>([
   RegistrationVerifyType.ORGANIZATION,
   RegistrationVerifyType.AUTHOR,
]);
