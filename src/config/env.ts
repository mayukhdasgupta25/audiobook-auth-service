import dotenv from "dotenv";
import path from "path";

const LOCALHOST_PATTERN = /localhost|127\.0\.0\.1/i;

const ENV_FILE_BY_NODE_ENV: Record<string, string | null> = {
   development: ".env.development",
   test: null,
   testing: ".env.testing",
   staging: ".env.staging",
   production: ".env.production",
};

function getEnvFileForBootstrap(): string | null {
   const bootstrapEnv = process.env["NODE_ENV"] ?? "development";
   return ENV_FILE_BY_NODE_ENV[bootstrapEnv] ?? `.env.${bootstrapEnv}`;
}

function loadEnvFiles(): void {
   const envFile = getEnvFileForBootstrap();
   if (envFile) {
      dotenv.config({ path: path.resolve(process.cwd(), envFile) });
   }
}

function requireEnv(key: string): string {
   const value = process.env[key];
   if (value === undefined) {
      throw new Error(`Missing required environment variable: ${key}`);
   }
   return value;
}

function requireIntEnv(key: string): number {
   const raw = requireEnv(key);
   const parsed = parseInt(raw, 10);
   if (Number.isNaN(parsed)) {
      throw new Error(`Environment variable ${key} must be a valid integer`);
   }
   return parsed;
}

function assertNoLocalhost(envVar: string, value: string, nodeEnv: string): void {
   if (LOCALHOST_PATTERN.test(value)) {
      throw new Error(`${envVar} must not reference localhost in ${nodeEnv}`);
   }
}

function validateNoLocalhostInStagingOrProduction(
   nodeEnv: string,
   values: {
      DATABASE_URL: string;
      REDIS_URL: string;
      RABBITMQ_URL: string;
      EMAIL_SERVICE_URL: string;
   }
): void {
   if (nodeEnv !== "staging" && nodeEnv !== "production") {
      return;
   }

   assertNoLocalhost("DATABASE_URL", values.DATABASE_URL, nodeEnv);
   assertNoLocalhost("REDIS_URL", values.REDIS_URL, nodeEnv);
   assertNoLocalhost("RABBITMQ_URL", values.RABBITMQ_URL, nodeEnv);

   if (values.EMAIL_SERVICE_URL) {
      assertNoLocalhost("EMAIL_SERVICE_URL", values.EMAIL_SERVICE_URL, nodeEnv);
   }
}

loadEnvFiles();

const nodeEnv = requireEnv("NODE_ENV");

const DATABASE_URL = requireEnv("DATABASE_URL");
const REDIS_URL = requireEnv("REDIS_URL");
const RABBITMQ_URL = requireEnv("RABBITMQ_URL");
const EMAIL_SERVICE_URL = requireEnv("EMAIL_SERVICE_URL");

validateNoLocalhostInStagingOrProduction(nodeEnv, {
   DATABASE_URL,
   REDIS_URL,
   RABBITMQ_URL,
   EMAIL_SERVICE_URL,
});

const USE_SECURE_COOKIES = nodeEnv === "production" || nodeEnv === "staging" || nodeEnv === "testing";

export const config = {
   NODE_ENV: nodeEnv,
   PORT: requireIntEnv("PORT"),
   USE_SECURE_COOKIES,
   TRUST_PROXY: requireIntEnv("TRUST_PROXY"),

   DATABASE_URL,
   SUBSCRIPTION_CURRENCY: requireEnv("SUBSCRIPTION_CURRENCY"),
   REDIS_URL,
   RABBITMQ_URL,
   RABBITMQ_EXCHANGE: requireEnv("RABBITMQ_EXCHANGE"),

   JWT_PRIVATE_KEY: requireEnv("JWT_PRIVATE_KEY"),
   JWT_PUBLIC_KEY: requireEnv("JWT_PUBLIC_KEY"),
   JWT_KEY_ID: requireEnv("JWT_KEY_ID"),
   JWT_ISSUER: requireEnv("JWT_ISSUER"),
   JWT_ACCESS_TOKEN_EXPIRY: requireEnv("JWT_ACCESS_TOKEN_EXPIRY"),
   JWT_REFRESH_TOKEN_EXPIRY: requireEnv("JWT_REFRESH_TOKEN_EXPIRY"),

   RATE_LIMIT_WINDOW_MS: requireIntEnv("RATE_LIMIT_WINDOW_MS"),
   RATE_LIMIT_MAX_REQUESTS: requireIntEnv("RATE_LIMIT_MAX_REQUESTS"),

   EMAIL_FROM: requireEnv("EMAIL_FROM"),
   EMAIL_SERVICE_URL,
   GOOGLE_CLIENT_ID: requireEnv("GOOGLE_CLIENT_ID"),

   ARGON2_MEMORY: requireIntEnv("ARGON2_MEMORY"),
   ARGON2_ITERATIONS: requireIntEnv("ARGON2_ITERATIONS"),
   ARGON2_PARALLELISM: requireIntEnv("ARGON2_PARALLELISM"),

   LOG_LEVEL: requireEnv("LOG_LEVEL"),
};
