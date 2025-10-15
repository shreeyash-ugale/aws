# JWT Token Migration

## Overview
The token system has been migrated from custom token implementation to standard JWT (JSON Web Tokens).

## Changes Made

### 1. Dependencies
- Added `github.com/golang-jwt/jwt/v5` to `go.mod`

### 2. Token Implementation (`internal/auth/tokens.go`)

#### Key Changes:
- **Replaced custom token generation** with JWT standard
- **JWT Secret**: Uses `ADMIN` token from `.env` as the JWT signing secret
- **Token Validity**: Default 24 hours (hardcoded as per requirement)
- **Signing Algorithm**: HS256 (HMAC-SHA256)

#### Token Structure:
```go
type TokenClaims struct {
    TokenID string `json:"jti"`  // Unique token identifier
    jwt.RegisteredClaims
}
```

JWT tokens now include:
- `jti` (Token ID): Unique identifier for revocation tracking
- `iat` (Issued At): Token creation timestamp
- `exp` (Expires At): Token expiration timestamp (24h from creation)
- `iss` (Issuer): "secureFile"

#### TokenRecord Structure:
```go
type TokenRecord struct {
    ID        string `json:"id"`        // Token ID
    IssuedAt  int64  `json:"issuedAt"`  // Unix timestamp
    ExpiresAt int64  `json:"expiresAt"` // Unix timestamp
    Revoked   bool   `json:"revoked"`   // Revocation status
}
```

### 3. Token Operations

#### CreateToken
- Generates a JWT token signed with the ADMIN secret
- Token validity: 24 hours
- Returns: token ID, JWT string, expiry timestamp

#### Validate
- Parses and validates JWT signature
- Checks token expiration (handled by JWT library)
- Verifies token is not revoked (checked against S3 cache)

#### Revoke
- Marks a token as revoked in S3 storage
- Revoked tokens are rejected during validation

#### List
- Returns all token metadata (for admin interface)

### 4. API Changes (`internal/api/routes.go`)
- Updated `NewTokenStore` initialization to pass `cfg.AdminToken` as JWT secret

### 5. Security Improvements
- **Standard JWT format**: Industry-standard, well-tested implementation
- **HMAC-SHA256 signing**: Strong cryptographic signature
- **Built-in expiry**: JWT library handles expiration validation
- **Revocation support**: Tokens can be revoked via admin API

## Usage

### Generate a Token (Admin)
```bash
POST /admin/tokens
Authorization: Bearer <ADMIN_TOKEN>

Response:
{
  "id": "tok_1729012345678901234",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresAt": 1729098745
}
```

### Use a Token
```bash
GET /files/{id}
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Revoke a Token (Admin)
```bash
POST /admin/tokens/{id}/revoke
Authorization: Bearer <ADMIN_TOKEN>
```

### List Tokens (Admin)
```bash
GET /admin/tokens
Authorization: Bearer <ADMIN_TOKEN>
```

## Environment Configuration

Required in `.env`:
```env
ADMIN_TOKEN=your-secret-admin-token-here
```

This `ADMIN_TOKEN` serves dual purposes:
1. Admin API authentication
2. JWT signing secret

## Migration Notes

### Breaking Changes
- **Token format changed**: Old custom tokens are not compatible with JWT tokens
- **All existing tokens need to be regenerated**
- Clients must request new JWT tokens from `/admin/tokens`

### Backward Compatibility
- None - this is a complete replacement of the token system
- Old tokens stored in S3 will not validate

### Storage
- Token metadata still stored in S3 at `config/tokens.json`
- Format changed to match new `TokenRecord` structure
- Supports revocation tracking

## Testing

1. Build the project: `go build`
2. Ensure `ADMIN_TOKEN` is set in `.env`
3. Start server: `./secureFile` (or `./aws.exe` on Windows)
4. Generate a token via admin API
5. Use the JWT token to access protected endpoints

## Technical Details

### JWT Claims Example
```json
{
  "jti": "tok_1729012345678901234",
  "iat": 1729012345,
  "exp": 1729098745,
  "iss": "secureFile"
}
```

### Token Validation Flow
1. Extract Bearer token from Authorization header
2. Parse JWT and verify HMAC signature using ADMIN secret
3. Check token expiration (automatic via JWT library)
4. Load token metadata from S3
5. Check if token is revoked
6. Allow/deny request based on validation result

### Revocation Strategy
- Tokens are cryptographically valid until expiration
- Revocation is enforced by checking metadata in S3
- Middleware reloads revocation list from S3 on each request
- Provides balance between security and performance
