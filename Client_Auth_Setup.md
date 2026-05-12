Looking at both files together, the current schema has a critical gap for external 3rd parties — there is **no `client_secret` column**. The existing accounts (admin-dashboard, monitoring) are internal services where `client_id` alone is acceptable, but a bank or merchant is an external party and must authenticate with both `client_id` + `client_secret`.

Here's everything needed:

---

## Information Required from Each 3rd Party

| Field | Bank | Merchant | Notes |
|---|---|---|---|
| Organisation name | e.g. `Stardomes Bank` | e.g. `Noon Payments` | For `account_name` |
| Desired scopes | `challenge:create`, `identity:verify` | `challenge:create`, `identity:verify` | What they need to do |
| Contact / technical owner | — | — | For audit trail |

You generate the `client_id` and `client_secret` yourself and hand them to the 3rd party — they don't supply them.

---

## Azure Key Vault — What to Store

The `client_secret` must never sit in the database in plaintext. Store a hashed version in the DB and the raw secret in Key Vault for initial provisioning/rotation.

| Secret Name | Value | Purpose |
|---|---|---|
| `idp-bank-stardomes-client-secret` | `<generated secret>` | Raw secret to hand to the bank |
| `idp-merchant-noon-client-secret` | `<generated secret>` | Raw secret to hand to the merchant |
| `AUTH-TOKEN-SECRET` | Already exists | JWT signing secret |

Generate the secrets:
```bash
# Generate a cryptographically strong client_secret for each
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Store in Key Vault:
```bash
az keyvault secret set \
  --vault-name vault-iot-test \
  --name idp-bank-stardomes-client-secret \
  --value "<generated-secret>"

az keyvault secret set \
  --vault-name vault-iot-test \
  --name idp-merchant-noon-client-secret \
  --value "<generated-secret>"
```

---

## Database DDL Changes

### Step 1 — Add `client_secret_hash` column to the existing table

```sql
-- Add client_secret_hash column (stores bcrypt/SHA-256 hash, never plaintext)
ALTER TABLE sa_service_accounts
  ADD client_secret_hash NVARCHAR(255) NULL;

EXEC sp_addextendedproperty
  @name=N'MS_Description',
  @value=N'SHA-256 hash of the client_secret. Raw secret stored in Azure Key Vault only.',
  @level0type=N'SCHEMA', @level0name=N'dbo',
  @level1type=N'TABLE',  @level1name=N'sa_service_accounts',
  @level2type=N'COLUMN', @level2name=N'client_secret_hash';
```

### Step 2 — Insert bank and merchant accounts

Replace `<SHA256_OF_BANK_SECRET>` and `<SHA256_OF_MERCHANT_SECRET>` with the hashed values (see below for how to generate them).

```sql
-- Bank: Stardomes Bank
IF NOT EXISTS (SELECT * FROM sa_service_accounts WHERE client_id = 'bank-stardomes')
BEGIN
    INSERT INTO sa_service_accounts
        (client_id, account_name, description, scopes, account_status, client_secret_hash)
    VALUES (
        'bank-stardomes',
        'Stardomes Bank',
        'Service account for Stardomes Bank — triggers CIBA authentication requests for payment approvals',
        '["challenge:create","identity:verify"]',
        'ACTIVE',
        '<SHA256_OF_BANK_SECRET>'
    );
    PRINT 'Service account bank-stardomes inserted.';
END
GO

-- Merchant: Noon Payments
IF NOT EXISTS (SELECT * FROM sa_service_accounts WHERE client_id = 'merchant-noon')
BEGIN
    INSERT INTO sa_service_accounts
        (client_id, account_name, description, scopes, account_status, client_secret_hash)
    VALUES (
        'merchant-noon',
        'Noon Payments',
        'Service account for Noon merchant — triggers CIBA authentication requests for purchase approvals',
        '["challenge:create","identity:verify"]',
        'ACTIVE',
        '<SHA256_OF_MERCHANT_SECRET>'
    );
    PRINT 'Service account merchant-noon inserted.';
END
GO
```

Generate the hashes to paste in:
```bash
# Replace <secret> with the value you stored in Key Vault
node -e "const c=require('crypto'); console.log(c.createHash('sha256').update('<secret>').digest('hex'))"
```

---

## Backend Code Change Required

[`auth.service.js`](src/services/auth.service.js) currently ignores `client_secret` entirely. It needs a new function for external 3rd party validation:

```javascript
// Add to auth.service.js
import crypto from 'crypto';

export async function issueAccessTokenForClient(clientId, clientSecret) {
  const account = await getServiceAccount(clientId);

  if (!account || account.account_status !== 'ACTIVE') return null;

  // Internal service accounts (no secret set) — reject if secret provided
  if (!account.client_secret_hash) {
    console.warn(`[AUTH] client_id ${clientId} has no secret configured`);
    return null;
  }

  // Validate secret
  const hash = crypto.createHash('sha256').update(clientSecret).digest('hex');
  if (hash !== account.client_secret_hash) {
    console.warn(`[AUTH] Invalid client_secret for ${clientId}`);
    return null;
  }

  const scopes = JSON.parse(account.scopes || '[]');
  return createToken(
    { sub: account.id, client_id: clientId, scope: scopes.join(' '), type: 'service' },
    TOKEN_SECRET,
    TOKEN_EXPIRY
  );
}
```

And update the token endpoint in [`admin.routes.js`](src/routes/admin.routes.js) to accept `client_secret` and route to the appropriate function:

```javascript
router.post('/v1/admin/auth/token', async (req, res) => {
  const { client_id, client_secret } = req.body;

  if (!client_id) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'client_id is required' });
  }

  // 3rd party external clients must supply client_secret
  // Internal accounts (admin-dashboard etc.) use client_id only
  const token = client_secret
    ? await authService.issueAccessTokenForClient(client_id, client_secret)
    : await authService.issueAccessToken(client_id);

  if (!token) {
    return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid credentials' });
  }

  res.json({ access_token: token, token_type: 'Bearer', expires_in: parseInt(process.env.AUTH_TOKEN_EXPIRY_SECONDS || '3600', 10) });
});
```

---

## What to Hand to the Bank / Merchant

```
IDP_BASE_URL    = https://idp-kong-gateway-poc-app.jollyforest-2769ae0c.uaenorth.azurecontainerapps.io
IDP_CLIENT_ID   = bank-stardomes          # or merchant-noon
IDP_CLIENT_SECRET = <raw secret from Key Vault>

# Token endpoint:
POST {IDP_BASE_URL}/v1/admin/auth/token
{ "client_id": "...", "client_secret": "..." }
```

Do you want me to implement the `auth.service.js` and `admin.routes.js` changes now?
