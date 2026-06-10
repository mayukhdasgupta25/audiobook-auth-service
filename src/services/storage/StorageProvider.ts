export interface StorageProvider {
   uploadFile(
      filePath: string,
      fileContent: Buffer,
      contentType?: string,
      metadata?: Record<string, string>
   ): Promise<string>;

   getFileUrl(filePath: string, expiresIn?: number): Promise<string>;
}

export interface StorageConfig {
   provider: 'local' | 's3';
   bucket?: string;
   region?: string;
   accessKeyId?: string;
   secretAccessKey?: string;
   endpoint?: string;
}
