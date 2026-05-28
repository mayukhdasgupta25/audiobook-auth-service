# Device tracking API (auth-service)

Users are limited to a number of registered devices based on their subscription plan (`SubscriptionPlan.features.maxDevices`, capped at 3). Users without an active subscription may use **1** device.

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

All routes require `Authorization: Bearer <accessToken>`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/devices` | List registered devices and limit info |
| DELETE | `/auth/devices/:id` | Remove a device; revokes refresh tokens for that device |

### GET `/auth/devices` response

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

## Error codes

| HTTP | Code | When |
|------|------|------|
| 400 | `DEVICE_ID_REQUIRED` | Missing or invalid `device.deviceId` on auth |
| 403 | `DEVICE_LIMIT_EXCEEDED` | New device would exceed plan limit |
| 403 | `DEVICE_CHANGES_NOT_ALLOWED` | Plan has `deviceChangesPerMonth: 0` |
| 403 | `DEVICE_CHANGE_QUOTA_EXCEEDED` | Monthly remove/add quota used |
| 403 | `DEVICE_NOT_REGISTERED` | Refresh token linked to a removed device |
| 404 | `DEVICE_NOT_FOUND` | DELETE target not found for user |

`DEVICE_LIMIT_EXCEEDED` responses include `details.maxDevices` and `details.registeredDevices`.

## Plan limits (seed defaults)

| Plan | maxDevices | deviceChangesPerMonth |
|------|------------|------------------------|
| Base | 1 | 0 |
| Standard | 2 | 1 |
| Premium | 3 | 3 |

## Flow

1. User signs in with `device.deviceId`.
2. Server registers the device or updates `lastSeenAt` if known.
3. If at limit and `deviceId` is new → `403 DEVICE_LIMIT_EXCEEDED`.
4. User removes a device via `DELETE /auth/devices/:id` (if plan allows), then signs in on the new device.
5. Removing a device revokes all refresh tokens bound to that device.
