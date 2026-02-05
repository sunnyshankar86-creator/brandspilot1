# BrandsPilot Auth API Examples

## Register
**Request**
```http
POST /auth/register
Content-Type: application/json

{
  "email": "jane.doe@brandspilot.ai",
  "password": "StrongPass123!",
  "role": "OWNER"
}
```

**Note:** Public registration assigns the `TEAM_MEMBER` role by default. Custom role assignment is restricted to privileged workflows.

**Response**
```json
{
  "accessToken": "<jwt-access-token>",
  "refreshToken": "<jwt-refresh-token>"
}
```

## Login
**Request**
```http
POST /auth/login
Content-Type: application/json

{
  "email": "jane.doe@brandspilot.ai",
  "password": "StrongPass123!"
}
```

**Response**
```json
{
  "accessToken": "<jwt-access-token>",
  "refreshToken": "<jwt-refresh-token>"
}
```

## Refresh Token
**Request**
```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "<jwt-refresh-token>"
}
```

**Response**
```json
{
  "accessToken": "<new-jwt-access-token>",
  "refreshToken": "<new-jwt-refresh-token>"
}
```

## Logout
**Request**
```http
POST /auth/logout
Authorization: Bearer <jwt-access-token>
```

**Response**
```http
204 No Content
```

## Protected Route
**Request**
```http
GET /auth/me
Authorization: Bearer <jwt-access-token>
```

**Response**
```json
{
  "id": "<user-id>",
  "email": "jane.doe@brandspilot.ai",
  "role": "OWNER",
  "status": "ACTIVE"
}
```

## Admin-only Route
**Request**
```http
GET /auth/admin-only
Authorization: Bearer <jwt-access-token>
```

**Response**
```json
{
  "message": "Admin access granted."
}
```

**Error (Forbidden)**
```json
{
  "statusCode": 403,
  "message": "Insufficient permissions.",
  "error": "Forbidden"
}
```
