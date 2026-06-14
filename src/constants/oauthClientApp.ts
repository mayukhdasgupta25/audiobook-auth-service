export const OAuthClientApp = {
   PARTNER: 'partner',
} as const;

export type OAuthClientAppValue = (typeof OAuthClientApp)[keyof typeof OAuthClientApp];
