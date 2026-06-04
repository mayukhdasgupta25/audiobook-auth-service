import { validateDeviceContext } from '../../src/utils/deviceValidation';
import { ValidationError } from '../../src/types';

describe('validateDeviceContext', () => {
   it('returns trimmed device context', () => {
      expect(
         validateDeviceContext({
            deviceId: '  abc-123  ',
            deviceName: ' Phone ',
            platform: 'ios',
         }),
      ).toEqual({
         deviceId: 'abc-123',
         deviceName: 'Phone',
         platform: 'ios',
      });
   });

   it('throws when deviceId is missing', () => {
      expect(() => validateDeviceContext({})).toThrow(ValidationError);
      try {
         validateDeviceContext({});
      } catch (error) {
         expect(error).toMatchObject({ code: 'DEVICE_ID_REQUIRED', statusCode: 400 });
      }
   });
});
