export interface StorageProvider {
   uploadFile(
      key: string,
      buffer: Buffer,
      contentType: string,
      metadata?: Record<string, string>,
   ): Promise<string>;

   getFileUrl(key: string, expiresIn?: number): Promise<string>;

   deleteFile(key: string): Promise<boolean>;

   fileExists(key: string): Promise<boolean>;
}

export interface StorageConfig {
   provider: 'local' | 's3';
   bucket?: string;
   region?: string;
   endpoint?: string;
}
