-- CreateEnum
CREATE TYPE "Gender" AS ENUM ('MALE', 'FEMALE', 'NON_BINARY', 'OTHER', 'PREFER_NOT_TO_SAY');

-- AlterTable
ALTER TABLE "users" ADD COLUMN "firstName" TEXT,
ADD COLUMN "lastName" TEXT,
ADD COLUMN "address" TEXT,
ADD COLUMN "contact" TEXT,
ADD COLUMN "gender" "Gender",
ADD COLUMN "location" TEXT,
ADD COLUMN "age" INTEGER;
