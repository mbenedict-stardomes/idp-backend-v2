# Stardomes IdP — Backend Build Plan v2.0

| Attribute       | Value                                                               |
| --------------- | ------------------------------------------------------------------- |
| **Version**     | 2.0                                                                 |
| **Runtime**     | Node.js on Azure Container Apps                                     |
| **Database**    | Azure SQL Server — `OIDC_DDL_v2.sql`                                |
| **Message Bus** | Azure Service Bus (topics: `sat.ingress`, `sat.uplink`)             |
| **Auth**        | mTLS + `private_key_jwt` (FAPI 2.0), DPoP sender-constrained tokens |
| **Gateway**     | Kong API Gateway (mTLS termination, routing, rate limiting)         |
| **RP ID**       | `stardomes.ae`                                                      |
| **App Origin**  | `https://app.stardomes.ae`                                          |
| **Issuer**      | `https://idp.stardomes.ae`                                          |
| **FIDO2 ACR**   | `urn:stardomes:acr:fido2`                                           |

---

## 1. Service Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL LAYER                              │
│                                                                     │
│   [Bank App / Fintech]          [Mobile App (iOS/Android)]          │
│         mTLS + private_key_jwt        Bearer + FIDO2 Assertion      │
│               │                               │                     │
└───────────────┼───────────────────────────────┼─────────────────────┘
                │                               │
                ▼                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     KONG API GATEWAY                                │
│       mTLS termination · rate limiting · routing · auth plugin      │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    AZURE CONTAINER APPS                             │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    IdP Core Service                         │    │
│  │                                                             │    │
│  │  /v1/oidc/*      /v1/ciba/*     /v1/app/*     /v1/admin/*   │    │
│  │  (OIDC/PAR/      (CIBA          (Identity/    (Client/      │    │
│  │   Token/JWKS)     Authorize)     Device/       Audit)       │    │
│  │                               Challenge)                    │    │
│  │                                                             │    │
│  │  ┌──────────────────────────────────────────────────────┐   │    │
│  │  │              src/fido2/                              │   │    │
│  │  │  challenge.js · attestation.js · assertion.js        │   │    │
│  │  │  formats/apple.js · formats/android-safetynet.js     │   │    │
│  │  └──────────────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌──────────────────────┐   ┌──────────────────────────────────┐    │
│  │  Ingress Worker      │   │  Scheduled Workers               │    │
│  │  (sat.ingress sub)   │   │  expired-challenge-cleaner       │    │
│  │  B-SB-03             │   │  B-FIDO2-05, B-AUTH-09           │    │
│  └──────────────────────┘   └──────────────────────────────────┘    │
└───────────┬──────────────────────────────────────┬──────────────────┘
            │                                      │
            ▼                                      ▼
┌────────────────────────┐              ┌─────────────────────────────┐
│   Azure SQL Server     │              │   Azure Service Bus         │
│   OIDC_DDL_v2.sql      │              │   sat.ingress (CIBA push)   │
│   13 tables · indexes  │              │   sat.uplink (APNs/FCM)     │
└────────────────────────┘              └─────────────────────────────┘
```

---

## 2. Backend Modules & Function Points

### 2.1 Module 1 — Identity Management (`ic_identity_core`)

| FP#     | Function             | Type  | Description                                                                                                                                                                                        |
| ------- | -------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B-IC-01 | createIdentity       | Write | Insert new user into `ic_identity_core`; generate UUID; validate unique `subject_identifier`                                                                                                       |
| B-IC-02 | getIdentityById      | Read  | Fetch identity record by UUID; used in all downstream flows                                                                                                                                        |
| B-IC-03 | resolveLoginHint     | Read  | For CIBA: iterate active identities; compute `SHA256(identity.subject_identifier + client.login_hint_salt)` per identity; return match. Must be constant-time per identity to resist timing oracle |
| B-IC-04 | updateIdentityStatus | Write | Set `identity_status` to LOCKED / SUSPENDED / REVOKED; cascade to block auth                                                                                                                       |
| B-IC-05 | listIdentities       | Read  | Admin-only paginated listing; filter by status; never return raw `subject_identifier` without admin scope                                                                                          |

### 2.2 Module 2 — National ID Verification (`nip` + `iva`)

| FP#      | Function                   | Type  | Description                                                                                                                                  |
| -------- | -------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| B-NID-01 | registerNationalIdProvider | Write | Insert UAE ICP or other government provider into `nip_national_id_provider`; store API endpoint and public key info                          |
| B-NID-02 | submitVerificationRequest  | Write | Call external provider API; write result to `iva_identity_verification_audit`; store `payload_checksum` (SHA-256 of response), never raw PII |
| B-NID-03 | getVerificationStatus      | Read  | Return current IAL level for an identity; used in token claims (`ial` claim)                                                                 |
| B-NID-04 | revokeVerification         | Write | Mark `iva` record REVOKED; downgrade IAL on identity; trigger audit log entry                                                                |

### 2.3 Module 3 — Device Registry (`idr_identity_device_registry`)

#### Base Device Operations (v1)

| FP#      | Function                    | Type         | Description                                                                                                                                                           |
| -------- | --------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B-DEV-01 | registerDeviceShell         | Write        | Create initial `idr` row with device metadata (model, OS, `device_permanent_id`); set `is_trusted = 0`, `attestation_verified = 0`; return `device_id`                |
| B-DEV-02 | verifyAttestation           | Orchestrator | Coordinate the full attestation verification pipeline (B-DEV-02a through B-DEV-02h); only call `setDeviceTrusted` after all sub-steps pass                            |
| B-DEV-03 | getDeviceById               | Read         | Fetch device record including `fido2_public_key_cbor`, `signature_counter`, `jailbroken`, `revoked`; used in assertion handler                                        |
| B-DEV-04 | getActiveDevicesForIdentity | Read         | SELECT from `idr` WHERE `identity_id = ?` AND `is_trusted = 1` AND `revoked = 0`; uses filtered index `idx_idr_trusted`                                               |
| B-DEV-05 | revokeDevice                | Write        | Set `revoked = 1`, `revoked_at = now()`, `revocation_reason`; revocation reasons: `DEVICE_LOST`, `COMPROMISED`, `REPLACED`, `POSSIBLE_CLONE_DETECTED`, `USER_REQUEST` |

#### Expanded — Attestation Verification Pipeline (v2)

| FP#       | Function                 | Type     | Description                                                                                                                                                                                                                                                            |
| --------- | ------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B-DEV-02a | decodeCBORAttestation    | Internal | `cbor.decode(base64urlDecode(attestationObject))` → extract `fmt` (format), `attStmt` (attestation statement), `authData` (binary buffer)                                                                                                                              |
| B-DEV-02b | parseAuthenticatorData   | Internal | Parse binary `authData`: `rpIdHash = authData.slice(0, 32)`, `flags = authData[32]`, `signCount = authData.readUInt32BE(33)`, `credentialData = authData.slice(37)` (contains `aaguid` + credential ID + COSE public key)                                              |
| B-DEV-02c | verifyRpIdHash           | Internal | Compute `SHA256("stardomes.ae")`; assert byte-equal to `authData.rpIdHash`; throw `rp_id_mismatch` if fail                                                                                                                                                             |
| B-DEV-02d | verifyAttestationFormat  | Internal | Route based on `fmt`: `"apple"` → `verifyAppleAttestation`, `"android-safetynet"` → `verifyAndroidAttestation`, `"packed"` → packed verifier, `"none"` → skip cert chain but still parse authData                                                                      |
| B-DEV-02e | verifyAppleAttestation   | Internal | Validate Apple attestation cert chain against Apple root CA (`apple-attestation-root.pem`); extract `aaguid` from leaf cert extension; verify `ctsProfileMatch` equivalent for Apple; if jailbreak indicator detected, set `jailbroken = 1` in device record           |
| B-DEV-02f | verifyAndroidAttestation | Internal | Decode SafetyNet JWS; verify JWT signature against Google root; assert `ctsProfileMatch = true` AND `basicIntegrity = true`; if either false, set `jailbroken = 1`                                                                                                     |
| B-DEV-02g | extractAndStorePublicKey | Write    | Parse CBOR `credentialData` from authData; extract COSE EC P-256 key map (`{1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes}`); store raw CBOR bytes in `idr.fido2_public_key_cbor` (VARBINARY); store `fido2_credential_id` (Base64URL credential ID from authenticator) |
| B-DEV-02h | setDeviceTrusted         | Write    | Only callable after B-DEV-02c through B-DEV-02g all pass without error: `UPDATE idr SET is_trusted = 1, attestation_verified = 1, aaguid = ?, signature_counter = 0, biometric_enrolled = 1, biometric_method = ? WHERE id = ?`                                        |

### 2.4 Module 3A — FIDO2 Challenge Manager (v2 new)

| FP#        | Function                        | Type       | Description                                                                                                                                                                                                                                                                                                                                                                               |
| ---------- | ------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B-FIDO2-01 | generateRegistrationChallenge   | Write      | `crypto.randomBytes(32)` → Base64URL encode → INSERT into `fcs_fido2_challenge_store` with `challenge_type = 'registration'`, `identity_id = NULL` (not yet known), `expires_at = now + 600s`, `consumed = 0`; return `{ session_id, challenge_b64url, timeout: 60000 }`                                                                                                                  |
| B-FIDO2-02 | storeChallenge                  | Write      | Generic insert into `fcs_fido2_challenge_store`; called by B-FIDO2-01 and B-FIDO2-04; fields: `session_id`, `challenge_bytes`, `challenge_b64url`, `challenge_type`, `identity_id`, `avr_id`, `ip_address`, `user_agent`, `expires_at`                                                                                                                                                    |
| B-FIDO2-03 | retrieveAndConsumeChallenge     | Read+Write | `SELECT TOP 1 * FROM fcs WHERE session_id = ? AND consumed = 0 AND expires_at > SYSUTCDATETIME()`; throw `challenge_expired` if no row found; then `UPDATE fcs SET consumed = 1, consumed_at = SYSUTCDATETIME() WHERE id = ? AND consumed = 0` (the `AND consumed = 0` predicate in the UPDATE makes this atomic — zero rows updated = already consumed = reject); return challenge bytes |
| B-FIDO2-04 | generateAuthenticationChallenge | Write      | `crypto.randomBytes(32)` → Base64URL encode → store in both `avr.challenge` and `fcs_fido2_challenge_store` (with `avr_id` FK); TTL = 300 seconds for authentication                                                                                                                                                                                                                      |
| B-FIDO2-05 | cleanExpiredChallenges          | Scheduled  | Cron (every 60 min): `DELETE FROM fcs_fido2_challenge_store WHERE expires_at < SYSUTCDATETIME()`; log count of deleted rows to audit log; also use `idx_fcs_expires` filtered index to avoid full scan                                                                                                                                                                                    |

### 2.5 Module 4 — Client Management (`cm_client_master` + `cub`)

| FP#      | Function            | Type     | Description                                                                                                                                            |
| -------- | ------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| B-CLT-01 | registerClient      | Write    | Insert into `cm_client_master`; generate `client_id_issued`; hash and store `client_secret`; set `login_hint_salt` (random 32 bytes, stored encrypted) |
| B-CLT-02 | getClientById       | Read     | Fetch client by UUID; used in token issuance and CIBA flow                                                                                             |
| B-CLT-03 | getClientByClientId | Read     | Fetch by `client_id_issued`; used in PAR and CIBA authorize flows                                                                                      |
| B-CLT-04 | validateClientAuth  | Internal | Verify `private_key_jwt` client assertion: check `iss`, `sub`, `aud`, `jti` (uniqueness); verify JWT signature against client's JWKS URI               |
| B-CLT-05 | createUserBinding   | Write    | Insert into `cub_client_user_binding`; generate pairwise `sub = HMAC-SHA256(identity_uuid, client_id + sector_salt)`; enforce UNIQUE constraint        |
| B-CLT-06 | getPairwiseSub      | Read     | Fetch `pairwise_sub` for (client, identity) pair; create if not exists; always return same value for same pair                                         |
| B-CLT-07 | suspendClient       | Write    | Set `client_status = 'SUSPENDED'`; blocks all OIDC and CIBA flows for that client                                                                      |

### 2.6 Module 5 — OIDC/CIBA Auth Engine (`avr`)

#### Base Auth Engine (v1)

| FP#       | Function               | Type         | Description                                                                                                                                                                                                      |
| --------- | ---------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B-AUTH-01 | processPAR             | Write        | `POST /v1/oidc/par`: validate client auth; validate request object (signed JWT); store PAR request; return `request_uri` with 90s TTL                                                                            |
| B-AUTH-02 | processCIBAAuthorize   | Write        | `POST /v1/ciba/authorize`: validate client; resolve `login_hint` via B-IC-03; create `avr` record (status=PENDING, challenge, expires_at=now+300s); publish to `sat.ingress`; return `auth_req_id`, `expires_in` |
| B-AUTH-03 | pollTokenEndpoint      | Read+Write   | `POST /v1/oidc/token` with `grant_type=urn:openid:params:grant-type:ciba`: check `avr.status`; if APPROVED → issue tokens; if PENDING → return `authorization_pending`; if EXPIRED → return `expired_token`      |
| B-AUTH-04 | issueAccessToken       | Write        | Generate JWT (ES256, `jti = UUID`); DPoP-bind via `cnf.jkt` thumbprint; insert into `tm_token_metadata`; set `acr_achieved = urn:stardomes:acr:fido2` for FIDO2 flows                                            |
| B-AUTH-05 | validateFIDO2Assertion | Orchestrator | Coordinate the full 9-step FIDO2 assertion verification (B-AUTH-05a through B-AUTH-05j); only advance to B-AUTH-05i (counter update) after all prior steps pass                                                  |
| B-AUTH-06 | invalidateAuthRequest  | Write        | Mark `avr.status = 'EXPIRED'` for stale PENDING requests; set `expired_at = SYSUTCDATETIME()`; scheduled worker runs every 60s                                                                                   |
| B-AUTH-07 | enforceMaxAttempts     | Write        | `avr.attempt_count++`; if `attempt_count >= max_attempts` → set `avr.status = 'LOCKED'`; return 429                                                                                                              |
| B-AUTH-08 | issueIdToken           | Write        | Generate ID token with pairwise `sub`, `acr`, `amr`, `iat`, `exp`, `aud` = client_id; sign with IdP private key                                                                                                  |
| B-AUTH-09 | expiredChallengeWorker | Scheduled    | Every 60s: `UPDATE avr SET status = 'EXPIRED', expired_at = SYSUTCDATETIME() WHERE status = 'PENDING' AND expires_at < SYSUTCDATETIME()`                                                                         |

#### Expanded — FIDO2 Assertion Verification Pipeline (v2)

| FP#        | Function                     | Type     | Description                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ---------- | ---------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B-AUTH-05a | decodeAssertionInputs        | Internal | Base64URL decode three fields from `assertion.response`: `authenticatorData` → `authDataBuf`, `clientDataJSON` → `clientDataBuf`, `signature` → `sigBuf`; also Base64URL decode `assertion.id` to use as credential lookup key                                                                                                                                                                                                                          |
| B-AUTH-05b | parseClientDataJSON          | Internal | `JSON.parse(clientDataBuf.toString('utf-8'))` → assert `clientData.type === 'webauthn.get'`; extract `challenge`, `origin`, `crossOrigin`; throw `invalid_client_data` if type wrong                                                                                                                                                                                                                                                                    |
| B-AUTH-05c | verifyChallenge              | Internal | `receivedChallenge = base64urlDecode(clientData.challenge)`; `storedChallenge = base64urlDecode(avr.challenge)`; assert `receivedChallenge.length === storedChallenge.length && crypto.timingSafeEqual(receivedChallenge, storedChallenge)`; throw `challenge_mismatch` on fail                                                                                                                                                                         |
| B-AUTH-05d | verifyOrigin                 | Internal | Assert `clientData.origin === 'https://app.stardomes.ae'`; assert `clientData.crossOrigin === false`; throw `origin_mismatch` and log security event if origin wrong                                                                                                                                                                                                                                                                                    |
| B-AUTH-05e | verifyRpIdHash               | Internal | `rpIdHash = authDataBuf.slice(0, 32)`; `expectedHash = crypto.createHash('sha256').update('stardomes.ae').digest()`; assert `rpIdHash.equals(expectedHash)`; throw `rp_id_mismatch` on fail                                                                                                                                                                                                                                                             |
| B-AUTH-05f | verifyUserFlags              | Internal | `flags = authDataBuf[32]`; `userPresent = (flags & 0x01) !== 0`; `userVerified = (flags & 0x04) !== 0`; assert both true; throw `user_not_present` or `user_not_verified` appropriately; UV = biometric required, not just physical presence                                                                                                                                                                                                            |
| B-AUTH-05g | verifySignCount              | Internal | `newSignCount = authDataBuf.readUInt32BE(33)`; assert `newSignCount > device.signature_counter` (strictly greater, never >=); if `newSignCount <= device.signature_counter` → call B-AUTH-05j (clone detection) immediately and return 401 without proceeding                                                                                                                                                                                           |
| B-AUTH-05h | verifyCryptographicSignature | Internal | `clientDataHash = crypto.createHash('sha256').update(clientDataBuf).digest()`; `signedData = Buffer.concat([authDataBuf, clientDataHash])`; `publicKeyDER = convertCOSEPublicKeyToDER(device.fido2_public_key_cbor)`; `isValid = crypto.verify('sha256', signedData, publicKeyDER, sigBuf)`; throw `invalid_signature` if `isValid === false`                                                                                                           |
| B-AUTH-05i | updateSignatureCounter       | Write    | Only called after all steps 05a–05h pass: `UPDATE idr SET signature_counter = newSignCount, last_active = SYSUTCDATETIME(), successful_auth_count = successful_auth_count + 1 WHERE id = device.id`; then `UPDATE avr SET status = 'APPROVED', validated_at = SYSUTCDATETIME(), sign_count = newSignCount, signature_data = sigBuf, authenticator_data_raw = authDataBuf, client_data_json = clientDataJSON, user_action = 'APPROVE' WHERE id = avr.id` |
| B-AUTH-05j | handleCloneDetection         | Write    | Triggered when `newSignCount <= stored_counter`: `UPDATE idr SET revoked = 1, revoked_at = SYSUTCDATETIME(), revocation_reason = 'POSSIBLE_CLONE_DETECTED' WHERE id = device.id`; write CRITICAL security event to `sal_secure_audit_log`; publish alert to security operations channel via Service Bus; return `{ error: 'cloning_detected' }` — do NOT allow auth to proceed under any circumstances                                                  |

### 2.7 Module 6 — Token Service (`tm_token_metadata`)

| FP#      | Function             | Type         | Description                                                                                                                                                                                 |
| -------- | -------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B-TKN-01 | issueTokenPair       | Orchestrator | Coordinate access token (B-AUTH-04) + ID token (B-AUTH-08) issuance; insert both into `tm_token_metadata`; return to bank                                                                   |
| B-TKN-02 | validateDPoP         | Internal     | Parse and verify DPoP proof JWT: check `htu` (request URI), `htm` (HTTP method), `iat` (within 5 min window), `jti` uniqueness; compute `cnf.jkt = base64url(SHA-256(DPoP public key JWK))` |
| B-TKN-03 | introspectToken      | Read         | `POST /v1/oidc/introspect`: return token metadata including `active`, `exp`, `cnf`, `acr`, `sub`; validate DPoP or mTLS binding before returning                                            |
| B-TKN-04 | revokeToken          | Write        | `POST /v1/oidc/revoke`: set `tm.revoked_at = now()`, `revocation_reason`; token is immediately invalid on next introspect                                                                   |
| B-TKN-05 | refreshToken         | Write        | Exchange refresh token → new access token; inherit `cnf_thumbprint` and `device_id`; invalidate old refresh token JTI                                                                       |
| B-TKN-06 | validateTokenBinding | Internal     | For each request bearing an access token: verify DPoP proof `ath` claim = `base64url(SHA-256(access_token))`; verify `cnf.jkt` matches DPoP public key                                      |
| B-TKN-07 | expiredTokenWorker   | Scheduled    | Hourly: delete (or mark tombstone) `tm` rows where `expires_at < now() AND revoked_at IS NULL`; uses `idx_tm_expires`                                                                       |

### 2.8 Module 7 — Key Management (`cki` + `kcl` + `krl`)

| FP#      | Function            | Type  | Description                                                                                                                                                                                                   |
| -------- | ------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B-KEY-01 | generateKeyPair     | Write | Generate RSA-4096 or EC P-256 key pair; store private key reference in Azure Key Vault; insert public JWK into `cki_crypto_key_inventory`; set `valid_from = now()`                                           |
| B-KEY-02 | getActiveSigningKey | Read  | Fetch `cki` row where `key_status = 'ACTIVE'` AND `key_use = 'sig'`; used for JWT signing; returns `key_alias` to resolve via KMS client                                                                      |
| B-KEY-03 | rotateSigningKey    | Write | Generate new key; insert ceremony record to `kcl`; update old key `key_status = 'ROTATED'`; activate new key; insert `krl` record; JWKS must serve both keys during transition period (`valid_to` of old key) |
| B-KEY-04 | serveJWKS           | Read  | `GET /v1/oidc/jwks`: return all active + recently rotated public JWKs; filter by `key_status IN ('ACTIVE','ROTATED')` AND `valid_to > now() OR valid_to IS NULL`                                              |
| B-KEY-05 | revokeKey           | Write | Emergency: set `key_status = 'REVOKED'`; all tokens signed with that key become immediately invalid; audit trail mandatory                                                                                    |

### 2.9 Module 8 — Audit Log (`sal_secure_audit_log`)

| FP#      | Function         | Type     | Description                                                                                                                                                                                                                                                                   |
| -------- | ---------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B-AUD-01 | appendAuditEvent | Write    | Insert into `sal_secure_audit_log`: compute `payload_hash = SHA-256(canonical_event_json)`; set `previous_row_hash = last_row.payload_hash` (hash-chain link); never allow UPDATE or DELETE                                                                                   |
| B-AUD-02 | verifyHashChain  | Read     | Admin: iterate all rows by `sequence_id`; recompute each `payload_hash`; verify each `previous_row_hash` links correctly; any break = tamper alert                                                                                                                            |
| B-AUD-03 | queryAuditLog    | Read     | `GET /v1/admin/audit`: filter by `actor_id`, `action_type`, `resource_type`, `correlation_id`, date range; paginated; admin scope required                                                                                                                                    |
| B-AUD-04 | appendFIDO2Event | Write    | Specialisation of B-AUD-01 for FIDO2 events: `action_type` ∈ `FIDO2_ASSERTION_SUCCESS`, `FIDO2_ASSERTION_FAILURE`, `FIDO2_CLONE_DETECTED`, `FIDO2_ATTESTATION_VERIFIED`, `FIDO2_DEVICE_REVOKED`; always include `device_id`, `correlation_id`, `sign_count` in `event_detail` |
| B-AUD-05 | signAuditRow     | Internal | Optionally sign each audit row with IdP private key (digital_signature column); provides non-repudiation beyond hash-chaining                                                                                                                                                 |

### 2.10 Module 9 — Service Bus Integration

| FP#     | Function                | Type     | Description                                                                                                                                                                                                  |
| ------- | ----------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| B-SB-01 | publishCIBARequest      | Write    | On `POST /v1/ciba/authorize`: publish message to `sat.ingress` topic: `{ auth_req_id, identity_uuid, challenge_b64url, binding_message, expires_at, correlation_id }`                                        |
| B-SB-02 | publishPushNotification | Write    | Ingress worker publishes to `sat.uplink` after resolving device token: `{ device_push_token, payload: { auth_req_id, binding_message, challenge } }`                                                         |
| B-SB-03 | ingressWorker           | Consumer | Subscribe to `sat.ingress`; look up active trusted devices for identity; generate push payload; publish to `sat.uplink`; handle dead-letter (device not found, identity locked) — dead-letter triggers alert |
| B-SB-04 | handleDeadLetter        | Internal | For each dead-lettered message: log to `sal_secure_audit_log`; update `avr.status = 'FAILED'`; notify ops team; for clone-detection events: page security team immediately                                   |

### 2.11 Module 10 — FIDO2 Utilities (v2 new)

| FP#        | Function                  | Type    | Description                                                                                                                                                                                                                                                                                                                                                                       |
| ---------- | ------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B-FIDO2-10 | base64URLEncode           | Utility | `buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')` — no padding, URL-safe characters                                                                                                                                                                                                                                                              |
| B-FIDO2-11 | base64URLDecode           | Utility | Add padding: `str + '='.repeat((4 - str.length % 4) % 4)`; replace `-` → `+`, `_` → `/`; `Buffer.from(padded, 'base64')`                                                                                                                                                                                                                                                          |
| B-FIDO2-12 | cborDecode                | Utility | `const cbor = require('cbor'); cbor.decodeFirstSync(buffer)` — returns JS object/Map; handles nested CBOR (attestation object contains CBOR-encoded authData)                                                                                                                                                                                                                     |
| B-FIDO2-13 | convertCOSEPublicKeyToDER | Utility | Parse CBOR COSE EC P-256 key map `{1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes}`; construct uncompressed point `Buffer.concat([Buffer.from([0x04]), x, y])`; wrap in SubjectPublicKeyInfo DER structure with EC P-256 OID (`1.2.840.10045.2.1` + curve OID `1.2.840.10045.3.1.7`); return as `KeyObject` via `crypto.createPublicKey({ key: der, format: 'der', type: 'spki' })` |
| B-FIDO2-14 | timingSafeEqual           | Utility | `if (a.length !== b.length) return false; return crypto.timingSafeEqual(a, b)` — length check must not short-circuit before `timingSafeEqual` to prevent timing oracle on length                                                                                                                                                                                                  |

---

## 3. FIDO2 Verification Pipeline

### 3.1 Overall FIDO2 Authentication Journey

```
PHASE 1: DEVICE ENROLLMENT (Registration)
──────────────────────────────────────────
T=0  App          → POST /v1/app/device/registration-challenge
     Backend      → crypto.randomBytes(32) → Base64URL
                  → INSERT fcs_fido2_challenge_store (type=registration, TTL=600s)
                  → return { challenge, rp, user, pubKeyCredParams, attestation }

T=1  Device       → OS generates EC P-256 FIDO2 keypair in Secure Enclave / KeyStore
                  → FaceID/TouchID enrolled — private key gated to biometric
                  → Creates attestation object (CBOR) signed by Apple/Google root

T=2  App          → POST /v1/app/device/register (attestation submission)
     Backend      → B-FIDO2-03: retrieve & consume challenge (anti-replay)
                  → B-DEV-02a through B-DEV-02h: full attestation pipeline
                  → Store fido2_public_key_cbor, fido2_credential_id, signature_counter=0
                  → B-DEV-02h: set is_trusted=1, attestation_verified=1

PHASE 2: 2FA REQUEST (Bank → Backend → Device)
───────────────────────────────────────────────
T=0  Bank         → POST /v1/ciba/authorize
                    { login_hint: SHA256(subject_id + bank_login_hint_salt),
                      binding_message, scope, acr_values: urn:stardomes:acr:fido2 }

T=0.1 Backend     → B-IC-03: iterate identities, match login_hint hash
                  → Create avr record (status=PENDING, expires_at=now+300s)
                  → B-FIDO2-04: generate auth challenge → store in avr.challenge + fcs
                  → B-SB-01: publish to sat.ingress
                  → Return { auth_req_id, expires_in: 300, interval: 5 }

T=0.3 IngressWorker (B-SB-03)
                  → Subscribe sat.ingress
                  → Look up active trusted devices for identity
                  → B-SB-02: publish to sat.uplink with challenge + binding_message
                  → Satellite terminal → APNs (iOS) / FCM (Android) push

T=0.5 Device      → Push received; notification shown with binding_message

PHASE 3: 2FA RESPONSE (Device → Backend — FIDO2 Assertion)
────────────────────────────────────────────────────────────
T=2  User         → Taps APPROVE → FaceID/TouchID prompt
                  → OS unlocks private key in Secure Enclave
                  → Signs: authData || SHA256(clientDataJSON) using ES256
                  → Creates assertion: { id, response: { clientDataJSON,
                    authenticatorData, signature, userHandle } }

T=2.1 App         → POST /v1/app/challenge/{auth_req_id}/respond
                    { action: "APPROVE", fido2_assertion: { ... } }

T=2.2 Backend     → B-AUTH-05: Run full 9-step assertion pipeline
                    Steps 05a → 05b → 05c → 05d → 05e → 05f → 05g → 05h
                    → If all pass: B-AUTH-05i: update counter, mark avr APPROVED
                    → If clone: B-AUTH-05j: revoke device, return 401

PHASE 4: TOKEN DELIVERY (Backend → Bank)
─────────────────────────────────────────
T=5  Bank         → POST /v1/oidc/token
                    { grant_type: urn:openid:params:grant-type:ciba, auth_req_id }

T=5.3 Backend     → Check avr.status === 'APPROVED'
                  → B-TKN-01: issue access_token + id_token
                    access_token: ES256, DPoP-bound (cnf.jkt)
                    id_token: pairwise sub, acr=urn:stardomes:acr:fido2, amr=fido
                  → Return to bank
```

### 3.2 Step-by-Step Assertion Verification Reference

This is the canonical implementation for `src/fido2/assertion.js`:

```javascript
// Input:
//   assertion.id                           → credential ID (Base64URL) — device lookup key
//   assertion.response.clientDataJSON      → Base64URL
//   assertion.response.authenticatorData   → Base64URL
//   assertion.response.signature           → Base64URL
//   assertion.response.userHandle          → Base64URL (optional)
//   avr.challenge                          → Base64URL (from DB)
//   device.fido2_public_key_cbor           → VARBINARY (from DB)
//   device.signature_counter               → BIGINT (from DB)

async function verifyFIDO2Assertion(assertion, avr, device) {
  // STEP 1: Decode all Base64URL inputs to Buffers
  const authDataBuf = base64URLDecode(assertion.response.authenticatorData);
  const clientDataBuf = base64URLDecode(assertion.response.clientDataJSON);
  const sigBuf = base64URLDecode(assertion.response.signature);

  // STEP 2: Parse clientDataJSON — verify type
  const clientData = JSON.parse(clientDataBuf.toString("utf-8"));
  if (clientData.type !== "webauthn.get")
    throw new FidoError("invalid_client_data");

  // STEP 3: Challenge verification — anti-replay, timing-safe
  const receivedChallenge = base64URLDecode(clientData.challenge);
  const storedChallenge = base64URLDecode(avr.challenge);
  if (
    receivedChallenge.length !== storedChallenge.length ||
    !crypto.timingSafeEqual(receivedChallenge, storedChallenge)
  ) {
    throw new FidoError("challenge_mismatch");
  }

  // STEP 4: Origin verification — anti-phishing
  if (clientData.origin !== "https://app.stardomes.ae") {
    await auditLog.append({
      action_type: "FIDO2_ORIGIN_MISMATCH",
      severity: "HIGH",
    });
    throw new FidoError("origin_mismatch");
  }
  if (clientData.crossOrigin === true) throw new FidoError("origin_mismatch");

  // STEP 5: Parse authenticator data binary structure
  const rpIdHash = authDataBuf.slice(0, 32); // bytes 0–31
  const flags = authDataBuf[32]; // byte 32
  const signCount = authDataBuf.readUInt32BE(33); // bytes 33–36 (big-endian uint32)

  // STEP 6: RP ID hash verification — domain binding
  const expectedRpIdHash = crypto
    .createHash("sha256")
    .update("stardomes.ae")
    .digest();
  if (!rpIdHash.equals(expectedRpIdHash)) throw new FidoError("rp_id_mismatch");

  // STEP 7: User presence (UP) and user verification (UV) flags
  const userPresent = (flags & 0x01) !== 0;
  const userVerified = (flags & 0x04) !== 0;
  if (!userPresent) throw new FidoError("user_not_present");
  if (!userVerified) throw new FidoError("user_not_verified"); // biometric required

  // STEP 8: Clone detection via signature counter
  // MUST be strictly greater than — equal signCount means replay or clone
  if (signCount <= device.signature_counter) {
    await handleCloneDetection(device); // B-AUTH-05j — revoke immediately
    throw new FidoError("cloning_detected");
  }

  // STEP 9: Cryptographic signature verification
  const clientDataHash = crypto
    .createHash("sha256")
    .update(clientDataBuf)
    .digest();
  const signedData = Buffer.concat([authDataBuf, clientDataHash]);
  const publicKeyDER = convertCOSEPublicKeyToDER(device.fido2_public_key_cbor);
  const isValid = crypto.verify("sha256", signedData, publicKeyDER, sigBuf);
  if (!isValid) throw new FidoError("invalid_signature");

  // STEP 10: Update state — only reached if all 9 steps pass
  await updateSignatureCounter(device.id, signCount); // B-AUTH-05i
  await markAVRApproved(avr.id, {
    signCount,
    sigBuf,
    authDataBuf,
    clientDataBuf,
  });
  return { verified: true, signCount };
}
```

### 3.3 AuthenticatorData Binary Layout

```
Byte offset   Length   Field
───────────────────────────────────────────────────────
0             32       rpIdHash     SHA-256 of rpId ("stardomes.ae")
32            1        flags        Bit field:
                                      bit 0 (0x01) = UP  (user present)
                                      bit 2 (0x04) = UV  (user verified / biometric)
                                      bit 6 (0x40) = AT  (attested credential data present)
33            4        signCount    Big-endian uint32; must increase on every auth
37+           var      credData     AT=1: aaguid(16) + credIdLen(2) + credId + COSE pubKey
```

---

## 4. FIDO2 Data Models

### 4.1 New Table: `fcs_fido2_challenge_store`

```sql
CREATE TABLE fcs_fido2_challenge_store (
    id                  UNIQUEIDENTIFIER NOT NULL DEFAULT NEWID(),

    -- Session & scope
    session_id          NVARCHAR(255)    NOT NULL,
    challenge_type      VARCHAR(20)      NOT NULL
                        CHECK (challenge_type IN ('registration','authentication')),
    identity_id         UNIQUEIDENTIFIER NULL,          -- NULL during registration (pre-enrollment)
    avr_id              UNIQUEIDENTIFIER NULL,          -- FK to avr for authentication challenges

    -- Challenge material
    challenge_bytes     VARBINARY(64)    NOT NULL,      -- Raw 32 bytes from crypto.randomBytes(32)
    challenge_b64url    NVARCHAR(255)    NOT NULL,      -- Base64URL sent to client

    -- Anti-replay consumption
    consumed            BIT              NOT NULL DEFAULT 0,
    consumed_at         DATETIME2        NULL,

    -- Audit context
    ip_address          NVARCHAR(45)     NULL,
    user_agent          NVARCHAR(MAX)    NULL,

    -- Timing: TTL = 600s (registration) / 300s (authentication)
    created_at          DATETIME2        NOT NULL DEFAULT SYSUTCDATETIME(),
    expires_at          DATETIME2        NOT NULL,

    CONSTRAINT PK_fcs_fido2_challenge_store PRIMARY KEY (id),
    CONSTRAINT FK_fcs_identity FOREIGN KEY (identity_id)
        REFERENCES ic_identity_core(id),
    CONSTRAINT FK_fcs_avr      FOREIGN KEY (avr_id)
        REFERENCES avr_authentication_validation_request(id)
);

-- Indexes (filtered for consumed = 0 — only active challenges matter)
CREATE INDEX idx_fcs_session       ON fcs_fido2_challenge_store (session_id, consumed)
                                   WHERE consumed = 0;
CREATE INDEX idx_fcs_expires       ON fcs_fido2_challenge_store (expires_at)
                                   WHERE consumed = 0;
CREATE INDEX idx_fcs_identity_type ON fcs_fido2_challenge_store (identity_id, challenge_type)
                                   WHERE consumed = 0;
```

### 4.2 `idr_identity_device_registry` — FIDO2 Columns (v2 additions)

All FIDO2-relevant columns added in v2 alongside preserved v1 columns:

| Column                  | Type             | Default | Notes                                                                                            |
| ----------------------- | ---------------- | ------- | ------------------------------------------------------------------------------------------------ |
| `device_public_key`     | NVARCHAR(MAX)    | NULL    | [v1] JWK/PEM string; human-readable; kept for backward compat                                    |
| `fido2_public_key_cbor` | VARBINARY(MAX)   | NULL    | [v2] CBOR-encoded COSE EC P-256 key; used by `crypto.verify()`                                   |
| `fido2_credential_id`   | NVARCHAR(MAX)    | NULL    | [v2] Base64URL credential ID; sent in every `assertion.id`; primary lookup key                   |
| `key_algorithm`         | VARCHAR(20)      | NULL    | [v2] `ES256` (default), `RS256`, `EdDSA`                                                         |
| `attestation_object`    | VARBINARY(MAX)   | NULL    | [v1] Original CBOR attestation blob; kept for audit replay                                       |
| `attestation_format`    | VARCHAR(30)      | NULL    | [v2] `apple`, `android-safetynet`, `packed`, `tpm`, `android-key`, `fido-u2f`, `none`            |
| `attestation_verified`  | BIT              | 0       | [v2] 1 = cert chain validated against platform root CA                                           |
| `aaguid`                | UNIQUEIDENTIFIER | NULL    | [v2] Authenticator GUID; identifies device model (e.g. iPhone 16)                                |
| `is_trusted`            | BIT              | 0       | [v1] 1 only after ALL attestation + security checks pass                                         |
| `jailbroken`            | BIT              | 0       | [v2] Set to 1 if attestation detects jailbreak/root; BLOCKS all auth                             |
| `signature_counter`     | BIGINT           | 0       | [v2] Must be BIGINT (FIDO2 spec uses uint32 max = 4,294,967,295); clone detection critical field |
| `biometric_enrolled`    | BIT              | 0       | [v2] Confirmed biometric gate on private key                                                     |
| `biometric_method`      | VARCHAR(25)      | NULL    | [v2] `FACEID`, `TOUCHID`, `ANDROID_BIOMETRIC`, `PIN`                                             |
| `successful_auth_count` | INT              | 0       | [v2] Total successful FIDO2 assertions                                                           |
| `failed_auth_count`     | INT              | 0       | [v2] Failed assertion attempts; rate-limiting signal                                             |
| `revoked`               | BIT              | 0       | [v2] Explicit revocation flag; enables efficient filtered index                                  |
| `revocation_reason`     | NVARCHAR(255)    | NULL    | [v2] `DEVICE_LOST`, `COMPROMISED`, `REPLACED`, `POSSIBLE_CLONE_DETECTED`, `USER_REQUEST`         |

**Critical index for assertion lookup:**

```sql
CREATE INDEX idx_idr_credential_id ON idr_identity_device_registry (fido2_credential_id);
CREATE INDEX idx_idr_revoked       ON idr_identity_device_registry (identity_id, revoked)
                                   WHERE revoked = 0;
CREATE INDEX idx_idr_sig_counter   ON idr_identity_device_registry (identity_id, signature_counter);
```

### 4.3 `avr_authentication_validation_request` — FIDO2 Columns (v2 additions)

| Column                   | Type           | Notes                                                                                                |
| ------------------------ | -------------- | ---------------------------------------------------------------------------------------------------- |
| `challenge`              | NVARCHAR(500)  | [v2] Base64URL encoded random 32 bytes; one-time use; distinct from `challenge_code_hash` (OTP)      |
| `challenge_created_at`   | DATETIME2      | [v2] When challenge bytes were generated                                                             |
| `correlation_id`         | NVARCHAR(255)  | [v2] Links sat.ingress → sat.uplink → avr → token for full cross-system tracing                      |
| `signature_data`         | VARBINARY(MAX) | [v2] Raw ECDSA signature bytes from `assertion.response.signature` (forensics/audit)                 |
| `authenticator_data_raw` | VARBINARY(MAX) | [v2] Raw authData buffer from assertion (forensics)                                                  |
| `client_data_json`       | NVARCHAR(MAX)  | [v2] Decoded clientDataJSON string (type, challenge, origin)                                         |
| `sign_count`             | BIGINT         | [v2] signCount from authData; recorded after clone-detection pass                                    |
| `user_action`            | VARCHAR(10)    | [v2] `APPROVE` or `DENY` (explicit device action)                                                    |
| `denial_reason`          | NVARCHAR(255)  | [v2] e.g. `UNRECOGNIZED_TRANSACTION`, `OTHER`                                                        |
| `denied_at`              | DATETIME2      | [v2] When DENY was recorded                                                                          |
| `expired_at`             | DATETIME2      | [v2] When cleanup worker set status=EXPIRED                                                          |
| `ip_address`             | NVARCHAR(45)   | [v2] Device IP at time of response (IPv4 or IPv6)                                                    |
| `user_agent`             | NVARCHAR(MAX)  | [v2] Device user-agent string                                                                        |
| `status`                 | VARCHAR(20)    | [v2 expanded] Added `FAILED` — FIDO2 signature verification failure (distinct from `DENIED` by user) |

### 4.4 `cm_client_master` — FIDO2 Column (v2 addition)

| Column            | Type          | Notes                                                                                                                                                                                                            |
| ----------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `login_hint_salt` | NVARCHAR(255) | [v2] Per-client secret salt. Bank computes `login_hint = SHA256(subject_id + salt)`. Backend iterates active identities, computes same hash, returns match. Must be stored encrypted (TDE or column encryption). |

---

## 5. API Contracts

### 5.1 OIDC Discovery

```
GET /.well-known/openid-configuration

Response 200:
{
  "issuer": "https://idp.stardomes.ae",
  "authorization_endpoint": "https://idp.stardomes.ae/v1/oidc/authorize",
  "token_endpoint": "https://idp.stardomes.ae/v1/oidc/token",
  "jwks_uri": "https://idp.stardomes.ae/v1/oidc/jwks",
  "backchannel_authentication_endpoint": "https://idp.stardomes.ae/v1/ciba/authorize",
  "pushed_authorization_request_endpoint": "https://idp.stardomes.ae/v1/oidc/par",
  "acr_values_supported": [
    "urn:stardomes:acr:fido2",
    "urn:stardomes:acr:otp",
    "urn:stardomes:acr:biometric"
  ],
  "backchannel_token_delivery_modes_supported": ["poll"],
  "dpop_signing_alg_values_supported": ["ES256"],
  "token_endpoint_auth_methods_supported": ["private_key_jwt", "tls_client_auth"]
}
```

### 5.2 PAR — Pushed Authorization Request

```
POST /v1/oidc/par
Content-Type: application/x-www-form-urlencoded
Authorization: (private_key_jwt in form body)

client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<signed JWT>
&request=<JAR signed request object>

Response 201:
{
  "request_uri": "urn:ietf:params:oauth:request_uri:<uuid>",
  "expires_in": 90
}

Error 400:
{ "error": "invalid_request", "error_description": "..." }
```

### 5.3 CIBA Authorize

```
POST /v1/ciba/authorize
Content-Type: application/x-www-form-urlencoded

client_id=<client_id>
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<signed JWT>
&login_hint=<SHA256(subject_id + login_hint_salt) — hex or base64url>
&scope=openid
&acr_values=urn:stardomes:acr:fido2
&binding_message=<human-readable tx description, max 128 chars>

Response 200:
{
  "auth_req_id": "<uuid>",
  "expires_in": 300,
  "interval": 5
}

Error 400 — login_hint not found:
{ "error": "unknown_user_id", "error_description": "login_hint could not be resolved." }

Error 400 — CIBA not enabled for client:
{ "error": "unauthorized_client" }
```

### 5.4 Token Endpoint (CIBA Poll)

```
POST /v1/oidc/token
Content-Type: application/x-www-form-urlencoded
DPoP: <DPoP proof JWT>

grant_type=urn:openid:params:grant-type:ciba
&auth_req_id=<uuid>
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<signed JWT>

Response 200 (APPROVED):
{
  "access_token": "<JWT>",
  "token_type": "DPoP",
  "expires_in": 3600,
  "id_token": "<JWT>",
  "scope": "openid"
}

Response 400 (still pending):
{ "error": "authorization_pending" }

Response 400 (expired):
{ "error": "expired_token" }

Response 400 (denied by user):
{ "error": "access_denied" }
```

### 5.5 JWKS

```
GET /v1/oidc/jwks

Response 200:
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "kid": "<key_alias>",
      "x": "<base64url>",
      "y": "<base64url>",
      "alg": "ES256"
    }
  ]
}
```

### 5.6 Device Registration — Step 1: Get Registration Challenge (v2 new endpoint)

```
POST /v1/app/device/registration-challenge
Authorization: Bearer <session_token>
Content-Type: application/json

Request Body:
{
  "identity_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
}

Response 200:
{
  "session_id": "<uuid>",
  "challenge": "<base64url-32-random-bytes>",
  "timeout": 60000,
  "rp": {
    "id": "stardomes.ae",
    "name": "Stardomes IdP"
  },
  "user": {
    "id": "<base64url-of-identity-uuid>",
    "name": "user@example.ae",
    "displayName": "Ahmed Al Mansoori"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },
    { "type": "public-key", "alg": -8 }
  ],
  "attestation": "direct",
  "userVerification": "required",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "userVerification": "required",
    "residentKey": "preferred"
  }
}

Error 401: { "error": "unauthorized" }
Error 404: { "error": "identity_not_found" }
```

### 5.7 Device Registration — Step 2: Submit Attestation

```
POST /v1/app/device/register
Authorization: Bearer <session_token>
Content-Type: application/json

Request Body:
{
  "session_id": "<uuid from step 1>",
  "identity_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "device_permanent_id": "<hardware-uuid-from-secure-enclave>",
  "device_model": "iPhone 16 Pro",
  "os_type": "IOS",
  "os_version": "19.2",
  "attestation_response": {
    "id": "<base64url-credential-id>",
    "rawId": "<base64url-raw-id>",
    "type": "public-key",
    "response": {
      "attestationObject": "<base64url-cbor-attestation>",
      "clientDataJSON": "<base64url-client-data>"
    }
  }
}

Response 201:
{
  "device_id": "<uuid>",
  "fido2_credential_id": "<base64url-credential-id>",
  "attestation_verified": true,
  "is_trusted": true,
  "registered_at": "2026-05-01T10:00:00Z",
  "message": "Device registered and trusted."
}

Error 400 — Challenge expired:
{ "error": "challenge_expired", "error_description": "Registration challenge has expired. Request a new one." }

Error 400 — Attestation failed:
{ "error": "attestation_verification_failed", "error_description": "Could not validate device attestation certificate chain." }

Error 400 — Jailbreak detected:
{ "error": "device_compromised", "error_description": "Device security posture does not meet requirements." }

Error 400 — RP ID mismatch:
{ "error": "rp_id_mismatch", "error_description": "Relying Party ID validation failed." }
```

### 5.8 Challenge Response — Full FIDO2 Assertion

```
POST /v1/app/challenge/{request_id}/respond
Content-Type: application/json
Authorization: Bearer <session_token>
X-Device-Id: <device_uuid>

Request Body (APPROVE — FIDO2):
{
  "action": "APPROVE",
  "fido2_assertion": {
    "id": "<base64url-credential-id>",
    "rawId": "<base64url-raw-id>",
    "type": "public-key",
    "response": {
      "clientDataJSON": "<base64url...>",
      "authenticatorData": "<base64url...>",
      "signature": "<base64url...>",
      "userHandle": "<base64url...>"
    }
  }
}

Request Body (DENY):
{
  "action": "DENY",
  "denial_reason": "UNRECOGNIZED_TRANSACTION"
}

Response 200 (success):
{
  "status": "APPROVED",
  "auth_req_id": "<uuid>"
}

FIDO2 Error Responses:

400 challenge_expired:
{ "error": "challenge_expired", "error_description": "Challenge has expired. Request a new authentication." }

401 challenge_mismatch:
{ "error": "challenge_mismatch", "error_description": "Challenge does not match stored value." }

401 origin_mismatch:
{ "error": "origin_mismatch", "error_description": "Request origin does not match expected origin." }

401 rp_id_mismatch:
{ "error": "rp_id_mismatch", "error_description": "Relying Party ID validation failed." }

401 user_not_present:
{ "error": "user_not_present", "error_description": "User presence was not confirmed." }

401 user_not_verified:
{ "error": "user_not_verified", "error_description": "Biometric verification was not performed." }

401 invalid_signature:
{ "error": "invalid_signature", "error_description": "FIDO2 cryptographic signature verification failed." }

401 cloning_detected:
{ "error": "cloning_detected", "error_description": "Authenticator clone detected; device has been revoked." }

401 device_not_found:
{ "error": "device_not_found", "error_description": "Credential ID not found or device not registered." }

401 device_revoked:
{ "error": "device_revoked", "error_description": "This device has been revoked. Contact support." }

401 device_not_trusted:
{ "error": "device_not_trusted", "error_description": "Device attestation has not been verified." }

401 device_compromised:
{ "error": "device_compromised", "error_description": "Device detected as jailbroken. Authentication blocked." }
```

### 5.9 Get Pending Challenge

```
GET /v1/app/challenge/pending
Authorization: Bearer <session_token>
X-Device-Id: <device_uuid>

Response 200:
{
  "request_id": "<auth_req_id>",
  "binding_message": "Approve transfer of AED 5,000 to Emirates NBD ending 4821",
  "expires_at": "2026-05-01T10:05:00Z",
  "auth_method": "FIDO2"
}

Response 204: (no pending challenge)
```

### 5.10 Device Revoke

```
POST /v1/app/device/{device_id}/revoke
Authorization: Bearer <session_token>

Request Body:
{
  "reason": "DEVICE_LOST"
}

Response 200:
{ "revoked": true, "revoked_at": "2026-05-01T10:00:00Z" }
```

### 5.11 Bank 2FA Status

```
POST /v1/bank/2fa
→ Same as POST /v1/ciba/authorize (bank-facing alias)

GET /v1/bank/2fa/{request_id}/status

Response 200:
{
  "status": "PENDING" | "APPROVED" | "DENIED" | "EXPIRED",
  "auth_req_id": "<uuid>",
  "expires_at": "2026-05-01T10:05:00Z"
}
```

### 5.12 Admin Endpoints

```
POST /v1/admin/clients        — register new OIDC client
GET  /v1/admin/audit          — paginated audit log query
POST /v1/app/identity/register         — create identity
POST /v1/app/identity/{id}/verify      — submit national ID verification
GET  /health                           — liveness + DB connectivity check
```

---

## 6. Backend Folder Structure

```
src/
├── app.js                          # Express app entry point; Kong health check
├── routes/
│   ├── oidc.js                     # GET /.well-known/openid-configuration
│   │                               # POST /v1/oidc/par
│   │                               # POST /v1/oidc/token
│   │                               # GET /v1/oidc/jwks
│   ├── ciba.js                     # POST /v1/ciba/authorize
│   ├── app-device.js               # POST /v1/app/device/registration-challenge (NEW)
│   │                               # POST /v1/app/device/register
│   │                               # POST /v1/app/device/{device_id}/revoke
│   ├── app-challenge.js            # GET /v1/app/challenge/pending
│   │                               # POST /v1/app/challenge/{request_id}/respond
│   ├── app-identity.js             # POST /v1/app/identity/register
│   │                               # POST /v1/app/identity/{id}/verify
│   ├── bank.js                     # POST /v1/bank/2fa
│   │                               # GET /v1/bank/2fa/{request_id}/status
│   └── admin.js                    # POST /v1/admin/clients
│                                   # GET /v1/admin/audit
├── fido2/                          # ── FIDO2 module (v2 new) ──────────────────
│   ├── challenge.js                # B-FIDO2-01 to B-FIDO2-05: challenge lifecycle
│   │                               #   generateRegistrationChallenge()
│   │                               #   generateAuthenticationChallenge()
│   │                               #   storeChallenge()
│   │                               #   retrieveAndConsumeChallenge()
│   │                               #   cleanExpiredChallenges()
│   ├── attestation.js              # B-DEV-02a to B-DEV-02h: attestation pipeline
│   │                               #   decodeCBORAttestation()
│   │                               #   parseAuthenticatorData()
│   │                               #   verifyRpIdHash()
│   │                               #   verifyAttestationFormat()
│   │                               #   extractAndStorePublicKey()
│   │                               #   setDeviceTrusted()
│   ├── assertion.js                # B-AUTH-05a to B-AUTH-05j: assertion pipeline
│   │                               #   verifyFIDO2Assertion() — full 9-step sequence
│   │                               #   handleCloneDetection()
│   │                               #   updateSignatureCounter()
│   └── formats/
│       ├── apple.js                # B-DEV-02e: Apple App Attest + Apple Anonymous
│       └── android-safetynet.js    # B-DEV-02f: SafetyNet JWS + Android Key
├── services/
│   ├── identity.js                 # B-IC-* functions
│   ├── device.js                   # B-DEV-01, B-DEV-03 to B-DEV-05
│   ├── auth.js                     # B-AUTH-01 to B-AUTH-04, B-AUTH-06 to B-AUTH-08
│   ├── token.js                    # B-TKN-* functions
│   ├── client.js                   # B-CLT-* functions
│   ├── key.js                      # B-KEY-* functions
│   └── audit.js                    # B-AUD-* functions
├── workers/
│   ├── ingress-worker.js           # B-SB-03: sat.ingress subscriber
│   ├── expired-challenge.js        # B-FIDO2-05 + B-AUTH-09: challenge/AVR cleanup
│   └── expired-token.js            # B-TKN-07: token cleanup
├── utils/
│   ├── crypto.js                   # JWT signing, SHA-256 hashing, DPoP verification
│   ├── fido2.js                    # B-FIDO2-10 to B-FIDO2-14:
│   │                               #   base64URLEncode()
│   │                               #   base64URLDecode()
│   │                               #   cborDecode()
│   │                               #   convertCOSEPublicKeyToDER()
│   │                               #   timingSafeEqual()
│   ├── hashchain.js                # B-AUD-01 to B-AUD-02: hash-chain audit
│   └── pairwise.js                 # B-CLT-05 to B-CLT-06: pairwise sub generation
├── db/
│   ├── pool.js                     # mssql connection pool
│   ├── identity.js                 # SQL queries for ic_identity_core
│   ├── device.js                   # SQL queries for idr_identity_device_registry
│   ├── avr.js                      # SQL queries for avr
│   ├── challenge.js                # SQL queries for fcs_fido2_challenge_store
│   ├── client.js                   # SQL queries for cm_client_master + cub
│   └── token.js                    # SQL queries for tm_token_metadata
├── middleware/
│   ├── auth.js                     # Bearer token validation
│   ├── mtls.js                     # mTLS client cert extraction
│   └── ratelimit.js                # Per-device rate limiting (5 attempts / 15 min)
└── config/
    ├── index.js                    # Environment config loader
    └── certs/
        ├── apple-attestation-root.pem
        └── google-safetynet-root.pem

npm dependencies (additions for v2):
  cbor           — CBOR encode/decode (attestation objects)
  cbor-x         — (alternative) faster CBOR implementation
  base64url      — Base64URL encode/decode utility
  @simplewebauthn/server — (optional) higher-level FIDO2 wrapper;
                           still implement manual pipeline per B-AUTH-05a–05j
```

---

## 7. FIDO2 Security Patterns

### 7.1 Timing-Safe Challenge Comparison

All comparisons of security-sensitive byte arrays must use `crypto.timingSafeEqual()`. A naive string comparison leaks timing information that can allow an attacker to learn the stored challenge byte-by-byte.

```javascript
// WRONG — timing leak (early exit on first mismatch)
if (receivedChallenge !== storedChallenge) {
  throw new Error("mismatch");
}

// CORRECT — constant time comparison
function timingSafeCompareB64(a, b) {
  const bufA = Buffer.from(a, "base64url");
  const bufB = Buffer.from(b, "base64url");
  // Length check must NOT short-circuit; pad to same length first
  // (different-length buffers cannot be passed to timingSafeEqual)
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
```

### 7.2 COSE Public Key → DER Conversion

The FIDO2 authenticator returns the public key as a CBOR-encoded COSE structure. Node.js `crypto.verify()` requires DER/SPKI format. This conversion must be exact.

```javascript
function convertCOSEPublicKeyToDER(coseKeyVarbinary) {
  // coseKeyVarbinary is a Buffer from idr.fido2_public_key_cbor
  const coseKey = cbor.decodeFirstSync(coseKeyVarbinary);

  // For EC P-256 (kty=2, alg=-7, crv=1):
  // coseKey.get(-2) = x coordinate (32 bytes)
  // coseKey.get(-3) = y coordinate (32 bytes)
  const x = coseKey.get(-2); // or coseKey[-2] depending on CBOR library
  const y = coseKey.get(-3);

  // Uncompressed EC point: 0x04 || x || y
  const ecPoint = Buffer.concat([Buffer.from([0x04]), x, y]);

  // Wrap in SubjectPublicKeyInfo (SPKI) DER structure
  // OID for EC public key: 1.2.840.10045.2.1
  // OID for P-256 curve:   1.2.840.10045.3.1.7
  const spkiPrefix = Buffer.from(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200",
    "hex",
  );
  const derBuffer = Buffer.concat([spkiPrefix, ecPoint]);

  return crypto.createPublicKey({
    key: derBuffer,
    format: "der",
    type: "spki",
  });
}
```

### 7.3 Clone Detection Trigger

On any assertion where `newSignCount <= device.signature_counter`, the backend must immediately revoke the device and halt the authentication. This check happens before the cryptographic signature verification is complete — a valid signature with a non-increasing counter still indicates cloning.

```javascript
async function handleCloneDetection(device) {
  // Step 1: Immediate revocation — do NOT allow auth to proceed
  await db.query(
    `
    UPDATE idr_identity_device_registry
    SET revoked = 1,
        revoked_at = SYSUTCDATETIME(),
        revocation_reason = 'POSSIBLE_CLONE_DETECTED'
    WHERE id = @deviceId AND revoked = 0
  `,
    { deviceId: device.id },
  );

  // Step 2: CRITICAL security event — hash-chained audit log
  await auditLog.append({
    actor_type: "SYSTEM",
    actor_id: "fido2-assertion-verifier",
    action_type: "FIDO2_CLONE_DETECTED",
    resource_type: "DEVICE",
    resource_id: device.id,
    event_detail: JSON.stringify({
      stored_counter: device.signature_counter,
      received_counter: newSignCount,
      identity_id: device.identity_id,
    }),
    severity: "CRITICAL",
  });

  // Step 3: Notify security operations
  await serviceBus.publishAlert({
    type: "CLONE_DETECTED",
    device_id: device.id,
    identity_id: device.identity_id,
    timestamp: new Date().toISOString(),
  });

  // Caller MUST return 401 cloning_detected immediately after this
}
```

### 7.4 Challenge Atomic Consumption (Anti-Replay)

Challenge consumption must be atomic to prevent two simultaneous requests from both succeeding with the same challenge. Use the SQL Server predicate update pattern:

```sql
-- The AND consumed = 0 makes this atomic — if another request already consumed it,
-- this UPDATE matches 0 rows → error, no race condition possible
UPDATE fcs_fido2_challenge_store
SET consumed = 1, consumed_at = SYSUTCDATETIME()
WHERE id = @challengeId AND consumed = 0;

-- Check @@ROWCOUNT immediately after
IF @@ROWCOUNT = 0
  THROW 50001, 'Challenge already consumed or not found', 1;
```

### 7.5 FIDO2 Error Taxonomy

| Error Code                        | HTTP | Recoverable                    | Trigger                           | Action                        |
| --------------------------------- | ---- | ------------------------------ | --------------------------------- | ----------------------------- |
| `challenge_expired`               | 400  | Yes — start new CIBA flow      | TTL exceeded                      | User starts over              |
| `challenge_mismatch`              | 401  | Yes — retry                    | clientDataJSON.challenge ≠ stored | Possible replay               |
| `origin_mismatch`                 | 401  | No — alert user                | clientDataJSON.origin wrong       | Log HIGH security event       |
| `rp_id_mismatch`                  | 401  | No                             | rpIdHash wrong                    | Log security event            |
| `user_not_present`                | 401  | Yes                            | UP flag not set                   | Re-prompt user                |
| `user_not_verified`               | 401  | Yes                            | UV flag not set                   | Biometric required            |
| `invalid_signature`               | 401  | Yes — retry                    | `crypto.verify()` returned false  | Increment `failed_auth_count` |
| `cloning_detected`                | 401  | No — re-enroll required        | signCount ≤ stored                | Revoke, page security ops     |
| `device_not_found`                | 401  | No                             | credential_id not in DB           | Re-enroll device              |
| `device_revoked`                  | 401  | No — contact support           | `idr.revoked = 1`                 | User contacts bank            |
| `device_compromised`              | 400  | No — re-enroll on clean device | `idr.jailbroken = 1`              | Refuse all auth               |
| `attestation_verification_failed` | 400  | No — re-enroll                 | Cert chain invalid                | Block device registration     |

---

## 8. Function Point Summary

| Module                                                         | V1 Count | V2 Additions | V2 Total |
| -------------------------------------------------------------- | -------- | ------------ | -------- |
| Identity Management (B-IC-\*)                                  | 5        | 0            | **5**    |
| National ID Verification (B-NID-\*)                            | 4        | 0            | **4**    |
| Device Registry — base (B-DEV-01 to 05)                        | 5        | 0            | 5        |
| Device Registry — attestation pipeline (B-DEV-02a to 02h)      | 0        | +8           | **8**    |
| Device Registry total                                          | 5        | +8           | **13**   |
| Client Management (B-CLT-\*)                                   | 7        | 0            | **7**    |
| OIDC/CIBA Auth Engine — base (B-AUTH-01 to 09)                 | 9        | 0            | 9        |
| OIDC/CIBA Auth Engine — assertion pipeline (B-AUTH-05a to 05j) | 0        | +10          | **10**   |
| OIDC/CIBA Auth Engine total                                    | 9        | +10          | **19**   |
| Token Service (B-TKN-\*)                                       | 7        | 0            | **7**    |
| Key Management (B-KEY-\*)                                      | 5        | 0            | **5**    |
| Audit Log (B-AUD-\*)                                           | 5        | 0            | **5**    |
| Service Bus (B-SB-\*)                                          | 4        | 0            | **4**    |
| **FIDO2 Challenge Manager (B-FIDO2-01 to 05)**                 | 0        | **+5**       | **5**    |
| **FIDO2 Utilities (B-FIDO2-10 to 14)**                         | 0        | **+5**       | **5**    |
| **TOTAL**                                                      | **51**   | **+28**      | **79**   |

---

## 9. Build Phases

### Phase 1 — Foundation (Week 1–2)

**Goal:** Database connectivity, identity CRUD, device registration shell, health, audit.

- Deploy Azure SQL Server; run `OIDC_DDL_v2.sql`
- Implement B-IC-01 to B-IC-05 (identity CRUD)
- Implement B-DEV-01, B-DEV-03, B-DEV-04, B-DEV-05 (device registry base)
- Implement B-AUD-01 to B-AUD-03 (hash-chain audit log)
- `GET /health` with DB ping check
- `POST /v1/app/identity/register`
- Unit tests: identity CRUD, device CRUD, audit hash chain verification

**Exit criteria:** Identity and device records persist; audit chain verifies; health endpoint returns 200.

---

### Phase 2 — OIDC Core (Week 3–4)

**Goal:** Client management, PAR, token issuance, JWKS, discovery.

- Implement B-CLT-01 to B-CLT-07 (client management + pairwise sub)
- Implement B-KEY-01 to B-KEY-05 (key generation, JWKS, rotation)
- Implement B-AUTH-01 (PAR)
- Implement B-AUTH-04, B-AUTH-08 (access token + ID token issuance)
- Implement B-TKN-01 to B-TKN-07 (token service including DPoP)
- `GET /.well-known/openid-configuration`
- `GET /v1/oidc/jwks`
- `POST /v1/oidc/par`
- `POST /v1/oidc/token` (authorization_code grant only at this stage)

**Exit criteria:** Full OIDC authorization_code flow with DPoP-bound tokens; JWKS served; discovery doc accurate.

---

### Phase 3 — CIBA & 2FA (Week 5–6)

**Goal:** CIBA flow, challenge delivery via Service Bus, challenge response (OTP/push), bank 2FA API, MFA fatigue controls.

- Implement B-IC-03 (login_hint resolution)
- Implement B-AUTH-02 (CIBA authorize — without FIDO2 assertion at this stage)
- Implement B-AUTH-03 (token polling)
- Implement B-AUTH-06, B-AUTH-07, B-AUTH-09 (MFA fatigue, expiry workers)
- Implement B-SB-01 to B-SB-04 (Service Bus ingress worker, push notification)
- `POST /v1/ciba/authorize`
- `GET /v1/app/challenge/pending`
- `POST /v1/app/challenge/{request_id}/respond` (DENY path; APPROVE with simple OTP)
- `POST /v1/bank/2fa` and `GET /v1/bank/2fa/{request_id}/status`

**Exit criteria:** End-to-end CIBA flow (bank → push → user responds → bank polls token).

---

### Phase 3B — FIDO2 Deep Implementation (Week 5B — parallel or immediately after Phase 3)

**Goal:** Full hardware-backed FIDO2 authentication. All 28 new function points implemented and tested.

- Implement `src/utils/fido2.js` (B-FIDO2-10 to B-FIDO2-14):
  - `base64URLEncode`, `base64URLDecode`
  - `cborDecode`
  - `convertCOSEPublicKeyToDER`
  - `timingSafeEqual`

- Implement `src/fido2/challenge.js` (B-FIDO2-01 to B-FIDO2-05):
  - Registration challenge generation (TTL=600s)
  - Authentication challenge generation (TTL=300s)
  - Atomic challenge consumption
  - Expiry cleanup cron

- Implement `src/fido2/attestation.js` + `formats/apple.js` + `formats/android-safetynet.js` (B-DEV-02a to B-DEV-02h):
  - CBOR decode attestation object
  - authData binary parsing (rpIdHash, flags, signCount, credentialData)
  - RP ID hash verification
  - Apple cert chain verification (against `apple-attestation-root.pem`)
  - Android SafetyNet JWS verification (against Google root)
  - Jailbreak detection → `jailbroken = 1`
  - COSE public key extraction → `fido2_public_key_cbor` (VARBINARY)
  - `setDeviceTrusted()` gating (only after all checks pass)

- Implement `src/fido2/assertion.js` (B-AUTH-05a to B-AUTH-05j):
  - Full 9-step verification pipeline (see Section 3.2)
  - Clone detection with immediate device revocation
  - Security event logging for CRITICAL events

- Add new endpoints:
  - `POST /v1/app/device/registration-challenge`
  - Update `POST /v1/app/device/register` to use full attestation flow
  - Update `POST /v1/app/challenge/{request_id}/respond` with all 11 FIDO2 error codes

- Unit tests (mandatory before Phase 4):
  - Challenge generation: verify 32-byte length, unique across 1000 calls
  - Base64URL roundtrip: encode then decode returns original bytes
  - CBOR decode: verify format and key extraction against known attestation fixture
  - `convertCOSEPublicKeyToDER`: verify output accepted by `crypto.verify()`
  - Full assertion pipeline: mock authenticator passes all 9 steps
  - Clone detection trigger: signCount = stored_counter → device revoked
  - Replay rejection: second use of consumed challenge returns error
  - Origin mismatch: wrong origin → `origin_mismatch` error
  - Jailbreak block: `jailbroken = 1` → all auth calls blocked

**Exit criteria:** Full FIDO2 registration + authentication works end-to-end. All production readiness checklist items checked. Zero flaky tests.

---

### Phase 4 — Hardening (Week 7–8)

**Goal:** Key rotation, hash-chain audit integrity, national ID verification, token revocation, scheduled workers, penetration test readiness.

- Implement B-KEY-03, B-KEY-05 (key rotation + emergency revocation)
- Implement B-NID-01 to B-NID-04 (national ID verification)
- Implement B-TKN-04, B-TKN-05 (token revocation + refresh)
- Implement B-AUD-02 (hash-chain verification admin tool)
- Implement B-AUD-05 (digital signature of audit rows)
- Complete scheduled workers (B-FIDO2-05, B-AUTH-09, B-TKN-07)
- Rate limiting middleware: 5 FIDO2 verification attempts per device per 15 minutes
- Load test: 100 concurrent CIBA flows
- Security review: verify `timingSafeEqual` used everywhere; no `===` on secrets
- Penetration test scope: FIDO2 replay, clone detection bypass attempts, origin injection

**Exit criteria:** FAPI 2.0 conformance test suite passes. Zero P1 vulnerabilities in pen test. All 79 function points implemented and integration-tested.

---

## 10. FIDO2 Production Readiness Checklist

The build is not complete until every item below is checked. This checklist aligns with Phase 3B exit criteria.

### Challenge Management

- [ ] Challenge generated with `crypto.randomBytes(32)` — never `Math.random()`, never predictable sequences
- [ ] Registration challenges stored with `expires_at = SYSUTCDATETIME() + 600s`
- [ ] Authentication challenges stored with `expires_at = SYSUTCDATETIME() + 300s`
- [ ] Challenge marked `consumed = 1` atomically on first use (SQL `UPDATE ... WHERE consumed = 0` pattern)
- [ ] Second use of same challenge returns error (replay test passes)
- [ ] Cron job cleans expired challenges at least every 60 minutes
- [ ] Base64URL encoding used consistently — never standard Base64 with `+`, `/`, `=`

### Attestation Verification

- [ ] CBOR decode of attestation object extracts `fmt`, `attStmt`, `authData` correctly
- [ ] authData binary parsing correct: `rpIdHash[0:32]`, `flags[32]`, `signCount[33:37]`, credentialData follows
- [ ] `rpIdHash` verified against `SHA256("stardomes.ae")` — not "app.stardomes.ae"
- [ ] Attestation cert chain verified for `fmt = "apple"` against `apple-attestation-root.pem`
- [ ] Attestation cert chain verified for `fmt = "android-safetynet"` — `ctsProfileMatch = true` AND `basicIntegrity = true`
- [ ] Jailbreak/root detection from attestation → `jailbroken = 1` → `auth` endpoint blocks with `device_compromised`
- [ ] AAGUID extracted from credential data and stored in `idr.aaguid`
- [ ] `is_trusted = 1` set **only** after ALL attestation checks pass — not before
- [ ] `signature_counter = 0` initialised at enrollment (not NULL)
- [ ] `fido2_public_key_cbor` stored as VARBINARY (raw bytes, not Base64 string)
- [ ] `fido2_credential_id` stored correctly (Base64URL string, used as assertion lookup key)

### Assertion Verification

- [ ] All 9 verification steps (B-AUTH-05a to B-AUTH-05i) implemented in sequence
- [ ] `timingSafeEqual` used for challenge comparison — no string `===`
- [ ] `crossOrigin` checked and must be `false`
- [ ] `UV` flag (0x04) enforced — biometric required, not just `UP` (0x01)
- [ ] `signCount > stored_counter` check is **strictly greater than** — `>=` is wrong
- [ ] Device auto-revoked on clone detection **before** any response is returned
- [ ] COSE → DER conversion produces a valid `KeyObject` (test with `crypto.verify()`)
- [ ] `signature_counter` updated in DB only after successful verification — not before
- [ ] `failed_auth_count` incremented on any failed assertion attempt
- [ ] Device lookup uses `fido2_credential_id` from `assertion.id` — not `device_id` from header alone

### Security Events & Monitoring

- [ ] All FIDO2 auth attempts (success and failure) logged to `sal_secure_audit_log`
- [ ] Clone detection: CRITICAL severity log entry + security ops alert (Service Bus or equivalent)
- [ ] Origin mismatch: HIGH severity security event logged
- [ ] Failed signature attempts tracked per device (`failed_auth_count`)
- [ ] Rate limiting active: max 5 FIDO2 verification attempts per device per 15 minutes
- [ ] Jailbroken device auth attempts logged with device ID and identity ID
- [ ] `correlation_id` propagated through: CIBA request → sat.ingress message → avr record → token

### Code Quality

- [ ] `src/utils/fido2.js` has 100% unit test coverage on all 5 utility functions
- [ ] No `console.log` of challenge bytes or signature data in production code
- [ ] Private key material never logged at any log level
- [ ] All FIDO2 error codes return structured JSON (never HTML error pages)
- [ ] `cbor` package pinned to exact version (avoid supply chain risk)
- [ ] Apple and Android root CA certificates stored in `src/config/certs/` and loaded at startup (not fetched at runtime)
