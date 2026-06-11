import fs from 'fs';
import path from 'path';
import { config } from '../config/env';
import { StorageFactory } from './storage/StorageFactory';

export type ImageKeyDirectory =
   | 'uploads/images/users'
   | 'uploads/images/authors';

export class FileUrlService {
   shouldSignUrls(): boolean {
      return config.NODE_ENV !== 'development';
   }

   async uploadLocalFileToStorage(
      localPath: string,
      s3Key: string,
      contentType: string,
   ): Promise<string> {
      const fileBuffer = fs.readFileSync(localPath);
      const storageProvider = StorageFactory.getStorageProvider();
      await storageProvider.uploadFile(s3Key, fileBuffer, contentType);
      return s3Key.replace(/\\/g, '/');
   }

   private toStorageKey(localPath: string, keyDirectory: ImageKeyDirectory): string {
      const normalized = path.normalize(localPath).replace(/\\/g, '/');
      const uploadsIndex = normalized.lastIndexOf('uploads/');

      if (uploadsIndex !== -1) {
         return normalized.slice(uploadsIndex);
      }

      return `${keyDirectory}/${path.basename(normalized)}`;
   }

   async processUploadedImageFile(
      localPath: string,
      keyDirectory: ImageKeyDirectory,
      contentType = 'image/jpeg',
      filenamePrefix = 'image',
   ): Promise<string> {
      if (!this.shouldSignUrls()) {
         return this.toStorageKey(localPath, keyDirectory);
      }

      const ext = path.extname(localPath) || '.jpg';
      const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
      const s3Key = `${keyDirectory}/${filenamePrefix}-${uniqueSuffix}${ext}`;

      return this.uploadLocalFileToStorage(localPath, s3Key, contentType);
   }
}

export const fileUrlService = new FileUrlService();
