import { FileUrlService } from '../../src/services/FileUrlService';
import { StorageFactory } from '../../src/services/storage/StorageFactory';

jest.mock('../../src/config/env', () => ({
   config: {
      NODE_ENV: 'testing',
      AWS_S3_BUCKET: 'test-bucket',
      AWS_S3_ENDPOINT: '',
      AWS_SIGNED_URL_EXPIRES_IN: 3600,
      DEV_UPLOAD_DIR: './src/uploads',
   },
}));

jest.mock('../../src/middleware/RegisterUploadMiddleware', () => ({
   getFileUrl: (filePath: string) => `/uploads${filePath.replace('./src/uploads', '')}`,
}));

describe('FileUrlService', () => {
   let service: FileUrlService;
   const mockGetFileUrl = jest.fn();
   const mockUploadFile = jest.fn();

   beforeEach(() => {
      service = new FileUrlService();
      mockGetFileUrl.mockReset();
      mockUploadFile.mockReset();
      mockGetFileUrl.mockResolvedValue('https://signed.example/object');
      mockUploadFile.mockResolvedValue('uploads/images/authors/image-1.jpg');

      jest.spyOn(StorageFactory, 'getStorageProvider').mockReturnValue({
         uploadFile: mockUploadFile,
         getFileUrl: mockGetFileUrl,
      } as never);
   });

   afterEach(() => {
      jest.restoreAllMocks();
   });

   describe('normalizeToS3Key', () => {
      it('returns uploads/ key as-is', () => {
         expect(service.normalizeToS3Key('uploads/images/authors/image-1.jpg')).toBe(
            'uploads/images/authors/image-1.jpg',
         );
      });

      it('strips leading /uploads/ prefix', () => {
         expect(service.normalizeToS3Key('/uploads/images/authors/image-1.jpg')).toBe(
            'uploads/images/authors/image-1.jpg',
         );
      });
   });

   describe('resolveForClient', () => {
      it('presigns S3 keys in non-development environments', async () => {
         const url = await service.resolveForClient('uploads/images/authors/image-1.jpg');

         expect(mockGetFileUrl).toHaveBeenCalledWith('uploads/images/authors/image-1.jpg', 3600);
         expect(url).toBe('https://signed.example/object');
      });
   });

   describe('processUploadedImageFile', () => {
      it('uploads to S3 and returns key in non-development', async () => {
         jest.spyOn(require('fs'), 'readFileSync').mockReturnValue(Buffer.from('data'));
         jest.spyOn(require('fs'), 'existsSync').mockReturnValue(true);
         jest.spyOn(require('fs'), 'unlinkSync').mockImplementation(() => undefined);

         const result = await service.processUploadedImageFile(
            '/tmp/image.jpg',
            'uploads/images/authors',
            'image/jpeg',
         );

         expect(mockUploadFile).toHaveBeenCalled();
         expect(result).toMatch(/^uploads\/images\/authors\/image-/);
      });
   });
});

describe('FileUrlService development mode', () => {
   beforeEach(() => {
      jest.resetModules();
   });

   it('returns /uploads URL for local files in development', async () => {
      jest.doMock('../../src/config/env', () => ({
         config: {
            NODE_ENV: 'development',
            AWS_S3_BUCKET: 'test-bucket',
            AWS_S3_ENDPOINT: '',
            AWS_SIGNED_URL_EXPIRES_IN: 3600,
            DEV_UPLOAD_DIR: './src/uploads',
         },
      }));

      jest.doMock('../../src/middleware/RegisterUploadMiddleware', () => ({
         getFileUrl: () => '/uploads/images/authors/image-1.jpg',
      }));

      const { FileUrlService: DevFileUrlService } = require('../../src/services/FileUrlService');
      const devService = new DevFileUrlService();

      const result = await devService.processUploadedImageFile(
         './src/uploads/images/authors/image-1.jpg',
         'uploads/images/authors',
         'image/jpeg',
      );

      expect(result).toBe('/uploads/images/authors/image-1.jpg');
   });
});
