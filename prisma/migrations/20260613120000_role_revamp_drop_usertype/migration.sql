-- Recreate Role enum with new values; migrate USER→LISTENER, ADMIN→GLOBAL_ADMIN
CREATE TYPE "Role_new" AS ENUM ('LISTENER', 'GLOBAL_ADMIN', 'ORG_ADMIN', 'ORG_COORDINATOR', 'AUTHOR');

ALTER TABLE "users" ALTER COLUMN "role" DROP DEFAULT;
ALTER TABLE "users" ALTER COLUMN "role" TYPE "Role_new" USING (
  CASE "role"::text
    WHEN 'USER' THEN 'LISTENER'::"Role_new"
    WHEN 'ADMIN' THEN 'GLOBAL_ADMIN'::"Role_new"
    WHEN 'AUTHOR' THEN 'AUTHOR'::"Role_new"
    ELSE 'LISTENER'::"Role_new"
  END
);
ALTER TABLE "users" ALTER COLUMN "role" SET DEFAULT 'LISTENER'::"Role_new";

DROP TYPE "Role";
ALTER TYPE "Role_new" RENAME TO "Role";

-- Drop UserType column and enum
ALTER TABLE "users" DROP COLUMN IF EXISTS "type";
DROP TYPE IF EXISTS "UserType";
