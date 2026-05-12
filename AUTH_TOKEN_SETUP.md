# Backend Auth Token Endpoint — Setup Guide

This document describes how to implement the `/v1/admin/auth/token` endpoint for the IdP backend service.

## Overview

The admin dashboard (web app) needs to authenticate to the backend API to access monitoring and management endpoints. The authentication uses a service account token exchange pattern:

```
1. Dashboard calls: POST /v1/admin/auth/token { client_id: "admin-dashboard" }
2. Backend validates client_id and issues JWT access token
3. Dashboard includes token in Authorization header for subsequent requests
```

## Implementation Steps

### Step 1: Database Setup

#### Option A: Using SQL Server Management Studio

Run the SQL script to create the service accounts table:

```bash
cd /Users/manohar/Documents/08_IdP_Development/00_Common_Layer/02_MSSQL/
# Execute in your MSSQL server:
sqlcmd -S empaysql-t.database.windows.net -d sqldb-authenticator-poc -U your_user -P your_password -i service-accounts-setup.sql
```

#### Option B: Using Azure Data Studio

1. Open [service-accounts-setup.sql](../02_MSSQL/service-accounts-setup.sql)
2. Connect to your MSSQL database
3. Execute the entire script

#### Option C: Using Azure CLI with MSSQL

```bash
# If using Azure SQL Database with Azure CLI
az sql db query \
  --resource-group rg-iot-test \
  --server empaysql-t \
  --database sqldb-authenticator-poc \
  --query-file /Users/manohar/Documents/08_IdP_Development/00_Common_Layer/02_MSSQL/service-accounts-setup.sql
```

**What the script does:**
- Creates `sa_service_accounts` table with columns: `id`, `client_id`, `account_name`, `scopes`, `account_status`
- Inserts the `admin-dashboard` service account
- Optionally inserts `monitoring-service` and `backup-export` accounts

### Step 2: Backend Code Update

The following files have been added/updated:

#### New Files:
- **[src/utils/jwt.js](#jwt-implementation)** — JWT token creation & verification
- **[src/services/auth.service.js](#auth-service)** — Service account lookup & token exchange
- **[service-accounts-setup.sql](#database-schema)** — Database migration script

#### Updated Files:
- **[src/routes/admin.routes.js](#admin-routes)** — Added `/v1/admin/auth/token` endpoint
- **[src/config/env.js](#environment-variables)** — Added `AUTH_TOKEN_SECRET` and `AUTH_TOKEN_EXPIRY_SECONDS`

### Step 3: Environment Variables

Set these in your `.env` or Azure Container Apps:

```bash
# Token signing secret (CHANGE THIS IN PRODUCTION!)
AUTH_TOKEN_SECRET=your-super-secret-key-change-in-production

# Token expiration time in seconds (default: 1 hour)
AUTH_TOKEN_EXPIRY_SECONDS=3600
```

**For Azure Container Apps:**

```bash
az containerapp update \
  --name idp-capp-service-poc-core \
  --resource-group rg-iot-test \
  --set-env-vars \
    AUTH_TOKEN_SECRET=your-production-secret-key \
    AUTH_TOKEN_EXPIRY_SECONDS=3600
```

### Step 4: Test the Endpoint

#### Local Development

```bash
# 1. Start the backend
cd /Users/manohar/Documents/08_IdP_Development/01_IdP_Solution/01_Backend
npm run dev

# 2. Request a token
curl -X POST http://localhost:8080/v1/admin/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"admin-dashboard"}'

# Expected response:
# {
#   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
#   "token_type": "Bearer",
#   "expires_in": 3600
# }

# 3. Use token to call admin endpoints
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
curl -X GET http://localhost:8080/v1/admin/identities \
  -H "Authorization: Bearer $TOKEN"
```

#### Azure Container Apps

```bash
# 1. Get the Kong gateway URL
az containerapp show \
  --name idp-kong-gateway-poc-app \
  --resource-group rg-iot-test \
  --query properties.configuration.ingress.fqdn

# 2. Request a token through Kong
curl -X POST https://idp-kong-gateway-poc-app.jollyforest-2769ae0c.uaenorth.azurecontainerapps.io/v1/admin/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"admin-dashboard"}'

# 3. Use token with your dashboard
```

## Implementation Details

### JWT Implementation

**File:** [src/utils/jwt.js](../01_IdP_Solution/01_Backend/src/utils/jwt.js)

Uses HMAC-SHA256 for token signing (no external JWT library required):

```javascript
import { createToken, verifyToken } from '../utils/jwt.js';

// Create token
const token = createToken(
  { sub: 'user-123', client_id: 'admin-dashboard' },
  'secret-key',
  3600  // expiry in seconds
);

// Verify token
const payload = verifyToken(token, 'secret-key');
// Returns: { sub: 'user-123', client_id: 'admin-dashboard', iat: ..., exp: ... }
// Or: null if invalid/expired
```

### Auth Service

**File:** [src/services/auth.service.js](../01_IdP_Solution/01_Backend/src/services/auth.service.js)

Handles service account operations:

```javascript
// Get service account details
const account = await authService.getServiceAccount('admin-dashboard');

// Issue access token
const token = await authService.issueAccessToken('admin-dashboard');

// Verify token (for middleware)
const payload = authService.verifyAccessToken(token);

// Extract bearer token from header
const token = authService.extractBearerToken(req.headers.authorization);
```

### Admin Routes

**File:** [src/routes/admin.routes.js](../01_IdP_Solution/01_Backend/src/routes/admin.routes.js)

The new endpoint:

```javascript
POST /v1/admin/auth/token

Request body:
{
  "client_id": "admin-dashboard"
}

Success response (200):
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600
}

Error responses:
400 - invalid_request: client_id is missing or invalid
401 - invalid_client: client_id not found or inactive
500 - server_error: database or signing error
```

## Securing Admin Endpoints

The code includes optional authentication middleware (currently commented out). To enforce token verification on all admin endpoints:

1. **Uncomment the middleware in [admin.routes.js](../01_IdP_Solution/01_Backend/src/routes/admin.routes.js):**

```javascript
// Uncomment these lines to enforce authentication:
router.use((req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authService.extractBearerToken(authHeader);
  if (!token) {
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'Missing or invalid Authorization header',
    });
  }
  const payload = authService.verifyAccessToken(token);
  if (!payload) {
    return res.status(401).json({
      error: 'unauthorized',
      error_description: 'Invalid or expired access token',
    });
  }
  req.service = payload;
  next();
});
```

2. **Rebuild and deploy:**

```bash
docker build -t idp-backend:latest .
docker push <acr>.azurecr.io/idp-backend:latest
az containerapp update --name idp-capp-service-poc-core --resource-group rg-iot-test --image <acr>.azurecr.io/idp-backend:latest
```

## Database Schema

**Table: `sa_service_accounts`**

| Column | Type | Notes |
|--------|------|-------|
| `id` | UNIQUEIDENTIFIER | Primary key (auto-generated) |
| `client_id` | NVARCHAR(255) | Service account identifier (UNIQUE) |
| `account_name` | NVARCHAR(255) | Human-readable name |
| `description` | NVARCHAR(MAX) | Purpose description |
| `scopes` | NVARCHAR(MAX) | JSON array of scopes |
| `account_status` | VARCHAR(20) | ACTIVE \| SUSPENDED \| REVOKED |
| `created_at` | DATETIME2 | Creation timestamp |
| `updated_at` | DATETIME2 | Last update |
| `revoked_at` | DATETIME2 | Revocation timestamp (if revoked) |
| `revocation_reason` | NVARCHAR(255) | Why was it revoked? |

## Service Accounts (Pre-configured)

### admin-dashboard

- **Purpose:** IdP Admin Web Console
- **Scopes:** `admin:monitoring`, `admin:identities`, `admin:audit`
- **Status:** ACTIVE

### monitoring-service

- **Purpose:** Monitoring and alerting systems
- **Scopes:** `admin:monitoring`, `metrics:read`
- **Status:** ACTIVE

### backup-export

- **Purpose:** Audit log exports and data backups
- **Scopes:** `audit:read`, `export:create`
- **Status:** ACTIVE

## Troubleshooting

### Error: "The provided credentials have insufficient access..."

This error comes from the backend when the token is missing or invalid.

**Check:**
1. Is `BACKEND_URL` set correctly in the dashboard container?
2. Is the token being sent in the `Authorization: Bearer <token>` header?
3. Are the service account credentials correct?

```bash
# Test token endpoint directly
curl -v -X POST http://localhost:8080/v1/admin/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"admin-dashboard"}'
```

### Error: "Service account not found"

The `admin-dashboard` account doesn't exist in the database.

**Fix:**
```bash
# Run the setup script again
sqlcmd -i service-accounts-setup.sql
```

### Tokens expire too quickly

Adjust `AUTH_TOKEN_EXPIRY_SECONDS`:

```bash
az containerapp update \
  --name idp-capp-service-poc-core \
  --resource-group rg-iot-test \
  --set-env-vars AUTH_TOKEN_EXPIRY_SECONDS=7200  # 2 hours
```

## Production Considerations

⚠️ **IMPORTANT**: Before deploying to production:

1. **Change `AUTH_TOKEN_SECRET`** to a strong, random value:
   ```bash
   # Generate a secure secret
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   
   # Store in Azure Key Vault
   az keyvault secret set \
     --vault-name vault-iot-test \
     --name AUTH-TOKEN-SECRET \
     --value "your-generated-secret"
   ```

2. **Consider RS256 instead of HS256** for distributed systems:
   - Switch to RSA public/private key signing
   - Use `jsonwebtoken` npm package: `npm install jsonwebtoken`

3. **Enable token encryption** for sensitive claims

4. **Implement token rotation** and revocation lists

5. **Add scope validation** in endpoint handlers

6. **Audit all token issuances** in logs

## Next Steps

1. ✅ Run the database setup script
2. ✅ Update backend environment variables
3. ✅ Rebuild and redeploy backend
4. ✅ Test token endpoint
5. ✅ Verify dashboard can authenticate

Once confirmed working, you can also:
- Uncomment the authentication middleware to enforce tokens
- Add scope validation to individual endpoints
- Implement token revocation endpoints
