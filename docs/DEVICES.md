# Device tracking API (auth-service)

Users with the **LISTENER** role are limited to a number of registered devices based on their subscription plan (`SubscriptionPlan.features.maxDevices`, capped at 3). Listeners without an active subscription may use **1** device.

**ORG_ADMIN**, **ORG_COORDINATOR**, **AUTHOR**, and **GLOBAL_ADMIN** are exempt from plan `maxDevices` and `deviceChangesPerMonth` enforcement. `GLOBAL_ADMIN` does not register devices at login.

## Client contract

Generate a stable UUID on first app launch and persist it in secure storage. Send it on every token-issuing auth request:

```json
{
  "email": "user@example.com",
  "password": "...",
  "device": {
    "deviceId": "550e8400-e29b-41d4-a716-446655440000",
    "deviceName": "Pixel 8",
    "platform": "android"
  }
}
```

Required on:

- `POST /auth/login`
- `POST /auth/login/mobile`
- `POST /auth/verify-registration-otp`
- `POST /auth/google`

`deviceId` is required (1–128 characters after trim).

## Device management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/devices` | JWT | List registered devices and limit info |
| POST | `/auth/devices/request-removal-otp` | None | `{ email, deviceId }` |
| POST | `/auth/devices/resend-removal-otp` | None | `{ email, deviceId }` — 30s after previous OTP |
| DELETE | `/auth/devices/:id` | None | `{ email, otp }` |

### GET `/auth/devices` response

Requires `Authorization: Bearer <accessToken>`.

```json
{
  "devices": [
    {
      "id": "uuid-row-id",
      "deviceId": "client-stable-id",
      "deviceName": "Pixel 8",
      "platform": "android",
      "lastSeenAt": "2026-05-27T12:00:00.000Z",
      "createdAt": "2026-05-01T10:00:00.000Z"
    }
  ],
  "limits": {
    "maxDevices": 2,
    "registeredCount": 1,
    "remainingDeviceChanges": 1
  }
}
```

### Remove a device (OTP flow)

Use this when the user cannot log in (e.g. `403 DEVICE_LIMIT_EXCEEDED`). Pick a device row `id` from `details.registeredDevices` in the login error response.

**Step 1 — Request OTP**

`POST /auth/devices/request-removal-otp`

```json
{
  "email": "user@example.com",
  "deviceId": "uuid-row-id"
}
```

**Step 1b — Resend OTP (optional)**

`POST /auth/devices/resend-removal-otp`

Same body as request. Only works if an active device-removal OTP already exists **and** at least **30 seconds** have passed since it was generated. Returns **429** `OTP_RESEND_COOLDOWN` with `details.remainingSeconds` if called too soon.

```json
{
  "email": "user@example.com",
  "deviceId": "uuid-row-id"
}
```

Always returns **200**:

```json
{
  "message": "If the account and device are eligible, an OTP has been sent to your email."
}
```

**Step 2 — Remove with OTP**

`DELETE /auth/devices/:id`

```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

On success, refresh tokens for that device are revoked and the device row is deleted.

Resend via `POST /auth/devices/resend-removal-otp` with the same `{ email, deviceId }` body (30s cooldown).

## Error codes

| HTTP | Code | When |
|------|------|------|
| 400 | `DEVICE_ID_REQUIRED` | Missing or invalid `device.deviceId` on auth |
| 400 | `INVALID_OTP` | Wrong or expired OTP on device removal |
| 400 | `DEVICE_REMOVAL_OTP_NOT_FOUND` | Resend called with no active device removal OTP |
| 429 | `OTP_RESEND_COOLDOWN` | Resend within 30s of previous OTP (`details.remainingSeconds`) |
| 403 | `DEVICE_LIMIT_EXCEEDED` | New device would exceed plan limit |
| 403 | `DEVICE_CHANGES_NOT_ALLOWED` | Plan has `deviceChangesPerMonth: 0` |
| 403 | `DEVICE_CHANGE_QUOTA_EXCEEDED` | Monthly remove/add quota used |
| 403 | `DEVICE_NOT_REGISTERED` | Refresh token linked to a removed device |
| 404 | `DEVICE_NOT_FOUND` | DELETE target not found for user |
| 404 | `USER_NOT_FOUND` | Email not found on device removal |

`DEVICE_LIMIT_EXCEEDED` responses include `details.maxDevices` and `details.registeredDevices`.

## Plan limits (seed defaults)

Applies to **LISTENER** accounts only.

| Plan | maxDevices | deviceChangesPerMonth |
|------|------------|------------------------|
| No subscription | 1 | 1 |
| Base | 1 | 0 |
| Standard | 2 | 1 |
| Premium | 3 | 3 |

## Flow

1. User signs in with `device.deviceId`.
2. Server registers the device or updates `lastSeenAt` if known.
3. If LISTENER is at limit and `deviceId` is new → `403 DEVICE_LIMIT_EXCEEDED` with `registeredDevices`.
4. User requests OTP for a device row id, then `DELETE /auth/devices/:id` with email + OTP.
5. User signs in on the new device.
6. Removing a device revokes all refresh tokens bound to that device.
