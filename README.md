# Auth Service

A secure authentication service built with Node.js, Express, TypeScript, and Prisma. This service provides JWT-based authentication with refresh token rotation, PKCE support, email verification, password reset, and Redis-based token revocation.

## Features

- **JWT Access Tokens**: RS256 signed tokens with 10-minute expiry
- **Opaque Refresh Tokens**: Cryptographically secure tokens with rotation
- **PKCE Support**: OAuth 2.0 PKCE flow for mobile clients
- **Email Verification**: Secure email verification with tokens
- **Password Reset**: Secure password reset flow
- **Role-Based Access Control**: USER and ADMIN roles
- **Redis Blocklist**: Token revocation and emergency revoke
- **JWKS Endpoint**: Public key endpoint for JWT verification
- **Rate Limiting**: Protection against brute force attacks
- **Security Headers**: Helmet.js and custom security middleware
- **TypeScript**: Full type safety throughout the application

## Architecture

```
auth-service/
├── src/
│   ├── config/          # Configuration management
│   ├── controllers/     # Route handlers
│   ├── middleware/      # Auth, rate limiting, error handling
│   ├── services/        # Business logic (auth, redis)
│   ├── utils/           # Crypto utilities (argon2, jwt, pkce)
│   ├── types/           # TypeScript interfaces
│   ├── routes/          # Express routes
│   ├── app.ts           # Express app setup
│   └── server.ts        # Server entry point
├── prisma/
│   └── schema.prisma    # Database schema
├── tests/               # Test files
└── package.json
```

## Prerequisites

- Node.js 18+
- PostgreSQL 13+
- Redis 6+
- npm or yarn

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd auth-service
```

2. Install dependencies:

```bash
npm install
```

3. Set up environment variables:

```bash
# For development (default)
cp env.example .env
# Edit .env with your configuration

# For staging (optional)
cp env.staging .env.staging
# Edit .env.staging with your configuration

# For production (optional)
cp env.production .env.production
# Edit .env.production with your configuration

# For local overrides (optional)
cp env.example .env.local
# Edit .env.local with your local overrides
```

4. Set up the database:

```bash
# Generate Prisma client
npm run db:generate

# Push schema to database (automatically uses correct environment)
npm run db:push

# Run migrations
npm run db:migrate
```

5. Generate JWT key pair (if not provided):

```bash
# Generate RSA key pair using Node.js
node -e "
const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
console.log('Private Key:');
console.log(privateKey);
console.log('Public Key:');
console.log(publicKey);
"
```

6. Seed the database with test users:

```bash
npm run db:seed
```

## Environment Variables

| Variable            | Description                            | Required | Default               |
| ------------------- | -------------------------------------- | -------- | --------------------- |
| `DATABASE_URL`      | PostgreSQL connection string           | Yes      | -                     |
| `REDIS_URL`         | Redis connection string                | Yes      | -                     |
| `RABBITMQ_URL`      | RabbitMQ connection string             | Yes      | -                     |
| `RABBITMQ_EXCHANGE` | RabbitMQ exchange name                 | No       | users                 |
| `JWT_PRIVATE_KEY`   | RSA private key for JWT signing        | Yes      | -                     |
| `JWT_PUBLIC_KEY`    | RSA public key for JWT verification    | Yes      | -                     |
| `JWT_KEY_ID`        | Key identifier for JWKS                | No       | auth-service-key-1    |
| `JWT_ISSUER`        | JWT issuer claim                       | No       | auth-service          |
| `PORT`              | Server port                            | No       | 3000                  |
| `NODE_ENV`          | Environment                            | No       | development           |
| `CORS_ORIGINS`      | Allowed CORS origins (comma-separated) | No       | http://localhost:3000 |

## Running the Application

### Development

```bash
# Development with hot reload
npm run dev

# Or start built application
npm run build
npm run start:dev
```

### Staging

```bash
npm run build
npm run start:staging
```

### Production

```bash
npm run build
npm run start:prod
```

## Environment Management

The application uses a simple environment loader (`src/env.ts`) that:

- Loads `.env.{NODE_ENV}` file based on the environment (e.g., `.env.staging`, `.env.production`)
- Falls back to `.env` for development
- Loads `.env.local` for local overrides (highest priority)
- Validates required environment variables

### Environment Files

- **Development**: `.env` - Default development settings
- **Staging**: `.env.staging` - Pre-production testing environment
- **Production**: `.env.production` - Production environment with strict security
- **Local Overrides**: `.env.local` - Local development overrides (ignored by git)

### Environment Commands

```bash
# Development
npm run dev                    # Start dev server
npm run db:push               # Push schema
npm run db:migrate            # Run migrations
npm run db:seed               # Seed database

# Staging
npm run dev:staging           # Start staging server

# Production
npm run start:prod            # Start production server
npm run db:migrate:prod       # Deploy migrations to production
```

## Test Users

After running the seed script (`npm run db:seed`), you'll have two test users:

**Normal User:**

- Email: `user@example.com`
- Password: `user123`
- Role: `USER`

**Admin User:**

- Email: `admin@example.com`
- Password: `admin123`
- Role: `ADMIN`

Both users are pre-verified and ready for testing authentication endpoints.

## RabbitMQ Integration

The auth service publishes user creation events to RabbitMQ for external services to consume.

### Configuration

- **Exchange**: `users` (topic exchange)
- **Routing Key**: `user.created`
- **Message Format**: `{"userId": "user-id-string"}`

### Event Publishing

When a user registers successfully, the service publishes a `user.created` event containing the user ID to the RabbitMQ exchange. External services can consume these events by:

1. Connecting to the same RabbitMQ instance
2. Declaring a queue bound to the `users` exchange with routing key `user.created`
3. Consuming messages from the queue

### Example Consumer Setup

```javascript
// External service consumer example
const amqp = require("amqplib");

async function consumeUserCreatedEvents() {
  const connection = await amqp.connect("amqp://localhost:5672");
  const channel = await connection.createChannel();

  // Declare queue
  const queue = "user-notifications";
  await channel.assertQueue(queue, { durable: true });

  // Bind to exchange
  await channel.bindQueue(queue, "users", "user.created");

  // Consume messages
  channel.consume(queue, (msg) => {
    if (msg) {
      const userData = JSON.parse(msg.content.toString());
      console.log("New user created:", userData.userId);
      // Process user creation event
      channel.ack(msg);
    }
  });
}
```

## API Endpoints

### Public Endpoints

#### Register User

```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

#### Login (Browser)

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123",
  "clientType": "browser"
}
```

#### Login (Mobile with PKCE)

```http
POST /auth/login/mobile
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123",
  "codeChallenge": "base64url-encoded-sha256-hash",
  "codeChallengeMethod": "S256"
}
```

#### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "opaque-refresh-token"
}
```

#### Verify Email

```http
POST /auth/verify-email
Content-Type: application/json

{
  "token": "email-verification-token"
}
```

#### Forgot Password

```http
POST /auth/forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Reset Password

```http
POST /auth/reset-password
Content-Type: application/json

{
  "token": "password-reset-token",
  "newPassword": "newSecurePassword123"
}
```

#### JWKS Endpoint

```http
GET /auth/.well-known/jwks.json
```

### Protected Endpoints

#### Get Current User

```http
GET /auth/me
Authorization: Bearer <access-token>
```

#### Change Password

```http
POST /auth/change-password
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "currentPassword": "currentPassword123",
  "newPassword": "newPassword123"
}
```

### Admin Endpoints

#### Revoke Token

```http
POST /auth/revoke
Authorization: Bearer <admin-access-token>
Content-Type: application/json

{
  "jti": "jwt-id-to-revoke"
}
```

#### Emergency Revoke All User Tokens

```http
POST /auth/emergency-revoke
Authorization: Bearer <admin-access-token>
Content-Type: application/json

{
  "userId": "user-id-to-revoke"
}
```

## JWT Token Structure

### Access Token Payload

```json
{
  "sub": "user-id",
  "email": "user@example.com",
  "role": "USER",
  "iat": 1640995200,
  "exp": 1640995800,
  "jti": "unique-token-id",
  "iss": "auth-service"
}
```

### Access Token Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "auth-service-key-1"
}
```

## Security Features

### Rate Limiting

- Login attempts: 5 per 15 minutes
- Password reset: 3 per hour
- Registration: 10 per hour
- General API: 100 per 15 minutes

### Password Security

- Argon2id hashing with secure defaults
- Memory: 65536 KB
- Iterations: 3
- Parallelism: 4

### Token Security

- Access tokens: 10-minute expiry
- Refresh tokens: 7-day expiry with rotation
- Token reuse detection and family revocation
- Redis-based revocation list

### PKCE Flow

1. Client generates `code_verifier` (random 32 bytes)
2. Client generates `code_challenge` (SHA256 of verifier, base64url encoded)
3. Client sends challenge with login request
4. Server stores challenge and user session
5. Client exchanges verifier for tokens

## Testing

Run tests:

```bash
npm test
```

Run tests in watch mode:

```bash
npm run test:watch
```

## Database Schema

### User Model

```prisma
model User {
  id            String    @id @default(uuid())
  email         String    @unique
  password      String    // Hashed password
  role          Role      @default(USER)
  emailVerified Boolean   @default(false)
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt
}
```

### Refresh Token Model

```prisma
model RefreshToken {
  id          String    @id @default(uuid())
  token       String    @unique
  userId      String
  expiresAt   DateTime
  createdAt   DateTime  @default(now())
  isRevoked   Boolean   @default(false)
  replacedBy  String?   // Token rotation tracking
}
```

## Integration with Other Services

### JWT Verification

Other services can verify JWT tokens by:

1. Fetching the JWKS endpoint: `GET /auth/.well-known/jwks.json`
2. Extracting the `kid` from the JWT header
3. Finding the matching public key in the JWKS
4. Verifying the JWT signature using the public key

### Example Verification (Node.js)

```javascript
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const client = jwksClient({
  jwksUri: "http://localhost:3000/auth/.well-known/jwks.json",
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

jwt.verify(
  token,
  getKey,
  {
    issuer: "auth-service",
    algorithms: ["RS256"],
  },
  (err, decoded) => {
    if (err) {
      console.error("Token verification failed:", err);
    } else {
      console.log("Token verified:", decoded);
    }
  }
);
```

## Monitoring and Logging

The service includes:

- Request logging with response times
- Error logging with stack traces
- Security event logging (token revocation, failed logins)
- Health check endpoint at `/health`

## Deployment

### Docker (Example)

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 3000
CMD ["npm", "start"]
```

### Environment Setup

- Ensure PostgreSQL and Redis are accessible
- Set all required environment variables
- Generate and configure JWT key pair
- Run database migrations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

MIT License - see LICENSE file for details.
