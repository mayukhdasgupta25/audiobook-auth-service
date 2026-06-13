import sizeOf from 'image-size';
import fs from 'fs';
import { ImageCategory, PrismaClient } from '@prisma/client';
import { DomainError } from '../types/domain';
import { AUTH_PRIMARY_VARIANT_KEY } from '../constants/imagePlaceholderSpecs';

export interface RecommendedMaxSpec {
   width: number;
   height: number;
   aspectRatioWidth: number;
   aspectRatioHeight: number;
   primaryVariantKey: string;
}

export class ImageSpecService {
   constructor(private readonly prisma: PrismaClient) {}

   async getSpecsByCategory(category: ImageCategory) {
      return this.prisma.imagePlaceholderSpec.findMany({
         where: { category },
         orderBy: [{ actualWidth: 'desc' }, { actualHeight: 'desc' }],
      });
   }

   async getRecommendedMax(category: ImageCategory): Promise<RecommendedMaxSpec> {
      const spec = await this.prisma.imagePlaceholderSpec.findFirst({
         where: { category },
      });

      if (!spec) {
         throw DomainError.internal('Image specs are not configured');
      }

      const primary = await this.prisma.imagePlaceholderSpec.findUnique({
         where: {
            category_variantKey: { category, variantKey: AUTH_PRIMARY_VARIANT_KEY },
         },
      });

      return {
         width: spec.recommendedMaxWidth,
         height: spec.recommendedMaxHeight,
         aspectRatioWidth: primary?.aspectRatioWidth ?? spec.aspectRatioWidth,
         aspectRatioHeight: primary?.aspectRatioHeight ?? spec.aspectRatioHeight,
         primaryVariantKey: AUTH_PRIMARY_VARIANT_KEY,
      };
   }

   async validateUpload(category: ImageCategory, filePath: string): Promise<void> {
      const recommended = await this.getRecommendedMax(category);
      const buffer = fs.readFileSync(filePath);
      const dimensions = sizeOf(buffer);

      if (!dimensions.width || !dimensions.height) {
         throw DomainError.validation('Unable to read image dimensions');
      }

      const { width, height } = dimensions;

      if (width < recommended.width || height < recommended.height) {
         throw DomainError.validation(
            `Image must be at least ${recommended.width}×${recommended.height}px. Received ${width}×${height}px.`
         );
      }

      const targetAspect = recommended.aspectRatioWidth / recommended.aspectRatioHeight;
      const actualAspect = width / height;
      const tolerance = 0.02;

      if (Math.abs(actualAspect - targetAspect) > tolerance) {
         throw DomainError.validation(
            `Image aspect ratio must be ${recommended.aspectRatioWidth}:${recommended.aspectRatioHeight}. Received ${width}×${height}px.`
         );
      }
   }
}
