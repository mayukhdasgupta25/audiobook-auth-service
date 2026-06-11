export const ClientType = {
   BROWSER: 'browser',
   MOBILE: 'mobile',
} as const;

export type ClientTypeValue = (typeof ClientType)[keyof typeof ClientType];
