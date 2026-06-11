/**
 * Upload middleware for author registration (multipart/form-data only).
 */
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { Request, Response, NextFunction } from 'express';
import { config } from '../config/env';

const ensureUploadDirs = (): void => {
   const dirs = [config.DEV_UPLOAD_DIR, config.DEV_AUTHOR_IMAGE_DIR];

   dirs.forEach((dir) => {
      if (!fs.existsSync(dir)) {
         fs.mkdirSync(dir, { recursive: true });
      }
   });
};

ensureUploadDirs();

const imageFilter = (_req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback): void => {
   const allowedMimes = [
      'image/jpeg',
      'image/jpg',
      'image/png',
      'image/gif',
      'image/webp',
   ];

   if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
   } else {
      cb(new Error('Only image files (JPEG, PNG, GIF, WebP) are allowed'));
   }
};

const authorImageStorage = multer.diskStorage({
   destination: (_req, _file, cb) => {
      cb(null, config.DEV_AUTHOR_IMAGE_DIR);
   },
   filename: (_req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
      const ext = path.extname(file.originalname);
      cb(null, `image-${uniqueSuffix}${ext}`);
   },
});

const authorRegistrationUpload = multer({
   storage: authorImageStorage,
   fileFilter: imageFilter,
   limits: {
      fileSize: config.MAX_FILE_SIZE,
      files: 1,
   },
});

const uploadAuthorRegistration = authorRegistrationUpload.fields([
   { name: 'profileImage', maxCount: 1 },
]);

export const handleUploadError = (error: unknown, _req: Request, res: Response, next: NextFunction): void => {
   if (error instanceof multer.MulterError) {
      if (error.code === 'LIMIT_FILE_SIZE') {
         res.status(400).json({
            error: 'File too large',
            code: 'FILE_TOO_LARGE',
         });
         return;
      }
      if (error.code === 'LIMIT_UNEXPECTED_FILE') {
         res.status(400).json({
            error: 'Unexpected file field. Expected profileImage.',
            code: 'UNEXPECTED_FILE_FIELD',
         });
         return;
      }
   }

   if (error instanceof Error && error.message.includes('Only image files')) {
      res.status(400).json({
         error: error.message,
         code: 'INVALID_FILE_TYPE',
      });
      return;
   }

   next(error);
};

export const getFileUrl = (filePath: string): string => {
   if (config.NODE_ENV === 'development') {
      const normalized = path.normalize(filePath).replace(/\\/g, '/');
      const uploadDir = path.normalize(config.DEV_UPLOAD_DIR).replace(/\\/g, '/').replace(/^\.\//, '');
      const relativePath = normalized.replace(/^\.\//, '');

      if (relativePath.startsWith(uploadDir)) {
         return `/uploads${relativePath.slice(uploadDir.length)}`;
      }

      const uploadsIndex = normalized.lastIndexOf('uploads/');
      if (uploadsIndex !== -1) {
         return `/${normalized.slice(uploadsIndex)}`;
      }

      return `/uploads/${path.basename(normalized)}`;
   }

   return filePath;
};

export const handleAuthorRegistrationUpload = (req: Request, res: Response, next: NextFunction): void => {
   const contentType = req.headers['content-type'] ?? '';

   if (!contentType.startsWith('multipart/form-data')) {
      next();
      return;
   }

   uploadAuthorRegistration(req, res, (err) => {
      if (err) {
         return handleUploadError(err, req, res, next);
      }

      const files = req.files as { [fieldname: string]: Express.Multer.File[] } | undefined;
      const profileImageFile = files?.['profileImage']?.[0];

      if (profileImageFile) {
         (req as Request & { profileImageFile?: Express.Multer.File }).profileImageFile = profileImageFile;
      }

      next();
   });
};
