import AWS from 'aws-sdk';
import { config } from '../../config/env';
import { StorageProvider, StorageConfig } from './StorageProvider';

export class S3StorageProvider implements StorageProvider {
   private readonly s3: AWS.S3;
   private readonly bucket: string;

   constructor(storageConfig?: Partial<StorageConfig>) {
      const options: AWS.S3.ClientConfiguration = {
         region: config.AWS_S3_REGION,
      };

      if (config.AWS_S3_ENDPOINT) {
         options.endpoint = config.AWS_S3_ENDPOINT;
         options.s3ForcePathStyle = true;
      }

      this.s3 = new AWS.S3(options);
      this.bucket = storageConfig?.bucket ?? config.AWS_S3_BUCKET;
   }

   async uploadFile(
      key: string,
      buffer: Buffer,
      contentType: string,
      metadata?: Record<string, string>,
   ): Promise<string> {
      const uploadParams: AWS.S3.PutObjectRequest = {
         Bucket: this.bucket,
         Key: key,
         Body: buffer,
         ContentType: contentType,
      };

      if (metadata) {
         uploadParams.Metadata = metadata;
      }

      await this.s3.upload(uploadParams).promise();

      return key.replace(/\\/g, '/');
   }

   async getFileUrl(key: string, expiresIn = config.AWS_SIGNED_URL_EXPIRES_IN): Promise<string> {
      return this.s3.getSignedUrl('getObject', {
         Bucket: this.bucket,
         Key: key,
         Expires: expiresIn,
      });
   }

   async deleteFile(key: string): Promise<boolean> {
      try {
         await this.s3
            .deleteObject({
               Bucket: this.bucket,
               Key: key,
            })
            .promise();
         return true;
      } catch {
         return false;
      }
   }

   async fileExists(key: string): Promise<boolean> {
      try {
         await this.s3
            .headObject({
               Bucket: this.bucket,
               Key: key,
            })
            .promise();
         return true;
      } catch {
         return false;
      }
   }
}
