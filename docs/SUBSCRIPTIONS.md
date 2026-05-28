# Subscription API (auth-service)

Subscription plans and user subscriptions live in **auth-service**. `UserSubscription.userId` references auth `User.id` (UUID).

## Endpoints

All require `Authorization: Bearer <accessToken>`.

### Plans — `/auth/subscription-plans`

| Method | Path | Access |
|--------|------|--------|
| GET | `/` | User |
| GET | `/:id` | User |
| POST | `/` | Admin |
| PUT | `/:id` | Admin |
| DELETE | `/:id` | Admin |

### Subscriptions — `/auth/subscriptions`

| Method | Path | Access |
|--------|------|--------|
| GET | `/me` | User — active subscription |
| GET | `/me/history` | User |
| GET | `/me/tier` | User — `{ tier: number \| null }` |
| GET | `/user/:userId` | Self or Admin |
| GET | `/` | Admin |
| POST | `/` | User (`planId`; optional `userId` for admin) |
| GET | `/:id` | User |
| PUT | `/:id` | User |
| POST | `/:id/cancel` | User |
| POST | `/:id/renew` | User — advances period; applies scheduled downgrade if due; records full-plan `RENEWAL_CHARGE` |
| POST | `/:id/change-plan` | User — body `{ planId }`; upgrade or schedule downgrade |
| DELETE | `/:id/pending-change` | User — cancel a scheduled downgrade |
| DELETE | `/:id` | Admin |

## Breaking changes from app-service

| Removed | Replacement |
|---------|-------------|
| `/api/v1/subscription-plans` | `/auth/subscription-plans` |
| `/api/v1/subscriptions/me` | `/auth/subscriptions/me` |
| `/api/v1/subscriptions/user/:userProfileId` | `/auth/subscriptions/user/:userId` |
| Body `userProfileId` | Body `userId` (UUID, admin for other users) |

## Seed plans

After migrations, seed Base, Standard, and Premium plans:

```bash
npm run db:seed
```

Skips if any plans already exist. Optional `SUBSCRIPTION_CURRENCY` (default `INR`).

Plan API responses include `features` (raw JSON) and `featureDescriptions` (sentences from `config/subscription-plan-features.en.yml`).

Plan `features.maxDevices` and `features.deviceChangesPerMonth` are enforced at login via device registration. See [DEVICES.md](./DEVICES.md).

## Plan changes (upgrade / downgrade)

`POST /auth/subscriptions/:id/change-plan` with `{ "planId": "<cuid>" }`.

- **Upgrade** (higher `tierLevel`): new plan applies **immediately**. A time-based **proration** charge is computed for the remainder of the current billing period and stored as `PRORATION_CHARGE` in `subscription_billing_events`. Response includes `prorationAmount`. Period dates are unchanged until renewal.
- **Downgrade** (lower `tierLevel`): current plan stays active until `currentPeriodEnd`. Response sets `pendingPlanId`, `pendingPlanChangeAt`, `pendingPlanChangeType: DOWNGRADE` and records `PLAN_CHANGE_SCHEDULED` (amount 0). Tier gating (`/me/tier`) uses the **current** plan until the change takes effect.
- **Renewal** (`POST /:id/renew`): if a pending downgrade is due, `planId` switches first; then the period advances and a **full** `RENEWAL_CHARGE` is recorded for the active plan price.
- **Cancel scheduled downgrade**: `DELETE /auth/subscriptions/:id/pending-change`.

Validation: target plan must be active, same `billingInterval` and `currency` as the current plan, and a different tier. Lifetime plans cannot change. During `TRIALING`, upgrades apply immediately with `prorationAmount: 0`.

Proration formula: `max(0, (newPrice - oldPrice) * remainingPeriodRatio)` where `remainingPeriodRatio` is the fraction of time left in `[currentPeriodStart, currentPeriodEnd]`.

Billing events are ledger-only (no payment gateway in auth-service); clients or a future payment service can consume `subscription_billing_events`.

## app-service gating

`GET /api/v1/audiobooks/:id` returns `subscriptionAccess` via `GET /auth/subscriptions/me/tier` using the same JWT. Set `AUTH_SERVICE_URL` in app-service.
