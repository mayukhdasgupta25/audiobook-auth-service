import AWS from 'aws-sdk';
import { config } from '../../config/env';
import { StorageProvider } from './StorageProvider';

export class S3StorageProvider implements StorageProvider {
   private readonly s3: AWS.S3;

   constructor() {
      const options: AWS.S3.ClientConfiguration = {
         region: config.AWS_S3_REGION,
         accessKeyId: config.AWS_ACCESS_KEY_ID,
         secretAccessKey: config.AWS_SECRET_ACCESS_KEY,
      };

      if (config.AWS_S3_ENDPOINT) {
         options.endpoint = config.AWS_S3_ENDPOINT;
         options.s3ForcePathStyle = true;
      }

      this.s3 = new AWS.S3(options);
   }

   async uploadFile(
      key: string,
      buffer: Buffer,
      contentType: string,
      metadata?: Record<string, string>,
   ): Promise<string> {
      const uploadParams: AWS.S3.PutObjectRequest = {
         Bucket: config.AWS_S3_BUCKET,
         Key: key,
         Body: buffer,
         ContentType: contentType,
      };

      if (metadata) {
         uploadParams.Metadata = metadata;
      }

      await this.s3.upload(uploadParams).promise();

      return key;
   }

   async getFileUrl(key: string, expiresIn: number): Promise<string> {
      return this.s3.getSignedUrl('getObject', {
         Bucket: config.AWS_S3_BUCKET,
         Key: key,
         Expires: expiresIn,
      });
   }

   async deleteFile(key: string): Promise<boolean> {
      try {
         await this.s3
            .deleteObject({
               Bucket: config.AWS_S3_BUCKET,
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
               Bucket: config.AWS_S3_BUCKET,
               Key: key,
            })
            .promise();
         return true;
      } catch {
         return false;
      }
   }
}
