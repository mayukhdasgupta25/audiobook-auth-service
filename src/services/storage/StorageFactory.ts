import { StorageProvider } from './StorageProvider';
import { S3StorageProvider } from './S3StorageProvider';

export class StorageFactory {
   private static instance: StorageProvider | null = null;

   public static getStorageProvider(): StorageProvider {
      if (!StorageFactory.instance) {
         StorageFactory.instance = new S3StorageProvider();
      }
      return StorageFactory.instance;
   }

   public static resetInstance(): void {
      StorageFactory.instance = null;
   }
}
