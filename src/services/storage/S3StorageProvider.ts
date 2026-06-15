import {
   S3Client,
   PutObjectCommand,
   GetObjectCommand,
   DeleteObjectCommand,
   HeadObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { config } from '../../config/env';
import { StorageProvider, StorageConfig } from './StorageProvider';

export class S3StorageProvider implements StorageProvider {
   private readonly s3Client: S3Client;
   private readonly bucket: string;

   constructor(storageConfig?: Partial<StorageConfig>) {
      this.s3Client = new S3Client({
         region: config.AWS_S3_REGION,
         ...(config.AWS_S3_ENDPOINT && {
            endpoint: config.AWS_S3_ENDPOINT,
            forcePathStyle: true,
         }),
      });
      this.bucket = storageConfig?.bucket ?? config.AWS_S3_BUCKET;
   }

   async uploadFile(
      key: string,
      buffer: Buffer,
      contentType: string,
      metadata?: Record<string, string>,
   ): Promise<string> {
      const command = new PutObjectCommand({
         Bucket: this.bucket,
         Key: key,
         Body: buffer,
         ContentType: contentType,
         ...(metadata && { Metadata: metadata }),
      });

      await this.s3Client.send(command);

      return key.replace(/\\/g, '/');
   }

   /**
    * Presigns a GET URL using AWS SDK v3 (Signature Version 4 only).
    */
   async getFileUrl(key: string, expiresIn = config.AWS_SIGNED_URL_EXPIRES_IN): Promise<string> {
      const command = new GetObjectCommand({
         Bucket: this.bucket,
         Key: key,
      });

      return getSignedUrl(this.s3Client, command, { expiresIn });
   }

   async deleteFile(key: string): Promise<boolean> {
      try {
         await this.s3Client.send(
            new DeleteObjectCommand({
               Bucket: this.bucket,
               Key: key,
            }),
         );
         return true;
      } catch {
         return false;
      }
   }

   async fileExists(key: string): Promise<boolean> {
      try {
         await this.s3Client.send(
            new HeadObjectCommand({
               Bucket: this.bucket,
               Key: key,
            }),
         );
         return true;
      } catch {
         return false;
      }
   }
}
