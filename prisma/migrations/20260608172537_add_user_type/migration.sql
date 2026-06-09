-- CreateEnum
CREATE TYPE "UserType" AS ENUM ('USER', 'AUTHOR');

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "type" "UserType" NOT NULL DEFAULT 'USER';
