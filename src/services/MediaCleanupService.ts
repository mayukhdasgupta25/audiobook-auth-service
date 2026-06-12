/**
 * Media cleanup helper — deletes stored files from S3 in non-development environments.
 */
import { config } from '../config/env';
import { fileUrlService } from './FileUrlService';
import { StorageFactory } from './storage/StorageFactory';

export class MediaCleanupService {
   private storageProvider = StorageFactory.getStorageProvider();

   async deleteStoredFile(stored: string | null | undefined): Promise<void> {
      if (!stored || config.NODE_ENV === 'development') {
         return;
      }

      const key = fileUrlService.normalizeToS3Key(stored);
      if (!key) {
         return;
      }

      try {
         await this.storageProvider.deleteFile(key);
      } catch (error) {
         console.error(`Failed to delete stored file ${key}:`, error);
      }
   }
}

export const mediaCleanupService = new MediaCleanupService();
