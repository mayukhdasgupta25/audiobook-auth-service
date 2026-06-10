import AWS from 'aws-sdk';
import { StorageProvider, StorageConfig } from './StorageProvider';
import { config } from '../../config/env';

export class S3StorageProvider implements StorageProvider {
   private s3: AWS.S3;
   private bucket: string;

   constructor(storageConfig?: Partial<StorageConfig>) {
      AWS.config.update({
         accessKeyId: config.AWS_ACCESS_KEY_ID,
         secretAccessKey: config.AWS_SECRET_ACCESS_KEY,
         region: config.AWS_S3_REGION,
      });

      this.s3 = new AWS.S3({
         ...(config.AWS_S3_ENDPOINT && { endpoint: config.AWS_S3_ENDPOINT }),
         s3ForcePathStyle: !!config.AWS_S3_ENDPOINT,
      });

      this.bucket = storageConfig?.bucket || config.AWS_S3_BUCKET;
   }

   async uploadFile(
      filePath: string,
      fileContent: Buffer,
      contentType = 'application/octet-stream',
   ): Promise<string> {
      const params: AWS.S3.PutObjectRequest = {
         Bucket: this.bucket,
         Key: filePath,
         Body: fileContent,
         ContentType: contentType,
      };

      await this.s3.upload(params).promise();
      return filePath.replace(/\\/g, '/');
   }

   async getFileUrl(filePath: string, expiresIn = config.AWS_SIGNED_URL_EXPIRES_IN): Promise<string> {
      return this.s3.getSignedUrl('getObject', {
         Bucket: this.bucket,
         Key: filePath,
         Expires: expiresIn,
      });
   }
}
