import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { Request, Response, NextFunction } from 'express';
import { config } from '../config/env';

const ensureUploadDirs = (): void => {
   const dirs = [config.DEV_UPLOAD_DIR, config.DEV_ORG_IMAGE_DIR];
   dirs.forEach((dir) => {
      if (!fs.existsSync(dir)) {
         fs.mkdirSync(dir, { recursive: true });
      }
   });
};

ensureUploadDirs();

const imageFilter = (_req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback): void => {
   const allowedMimes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
   if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
   } else {
      cb(new Error('Only image files (JPEG, PNG, GIF, WebP) are allowed'));
   }
};

const organizationImageStorage = multer.diskStorage({
   destination: (_req, _file, cb) => {
      cb(null, config.DEV_ORG_IMAGE_DIR);
   },
   filename: (_req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
      const ext = path.extname(file.originalname);
      cb(null, `image-${uniqueSuffix}${ext}`);
   },
});

const organizationUpload = multer({
   storage: organizationImageStorage,
   fileFilter: imageFilter,
   limits: {
      fileSize: config.MAX_FILE_SIZE,
      files: 1,
   },
});

export const handleOptionalOrganizationImageUpload = (
   req: Request,
   res: Response,
   next: NextFunction,
): void => {
   organizationUpload.single('image')(req, res, (error: unknown) => {
      if (error instanceof multer.MulterError) {
         if (error.code === 'LIMIT_FILE_SIZE') {
            res.status(400).json({ error: 'File too large', code: 'FILE_TOO_LARGE' });
            return;
         }
         res.status(400).json({ error: error.message, code: 'UPLOAD_ERROR' });
         return;
      }
      if (error instanceof Error) {
         res.status(400).json({ error: error.message, code: 'UPLOAD_ERROR' });
         return;
      }
      if (req.file) {
         (req as Request & { organizationImageFile?: Express.Multer.File }).organizationImageFile = req.file;
      }
      next();
   });
};
