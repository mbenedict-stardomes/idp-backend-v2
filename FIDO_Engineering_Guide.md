# FIDO2 Backend Engineering Guide

## Comprehensive Architecture, Implementation Patterns & Response Processing

---

## 📋 Table of Contents

1. [Challenge Generation Flow](#challenge-generation-flow)
2. [Response Processing Pipeline](#response-processing-pipeline)
3. [Verification Checks](#verification-checks)
4. [Code Implementation Examples](#code-implementation-examples)
5. [Data Models & Storage](#data-models--storage)
6. [Security Considerations](#security-considerations)
7. [Error Handling & Recovery](#error-handling--recovery)

---

## Challenge Generation Flow

### 1.1 Architecture Overview

```
User Request → Generate Challenge → Store in Session → Return to Browser
     ↓              ↓                    ↓                    ↓
  /login      cryptographic     Redis/Memory/DB         JSON Response
             random bytes       + expiration           {challenge, options}
```

### 1.2 Challenge Structure

A FIDO2 challenge is **32+ random bytes** (typically 32-64 bytes) that serves as a one-time nonce to:

- **Prevent replay attacks**: Each challenge is unique and time-bound
- **Bind to the transaction**: Challenge is included in both challenge options AND in the authenticator's signed response
- **Prove freshness**: Guarantees the authenticator response is for THIS authentication attempt

```
Challenge Lifecycle:
  Generated    →   Stored     →   Sent to    →   Included in    →   Verified
  (random)    →  (w/expiry)  →  Browser    →   Signed Response →  (must match)
    t=0       →    t=0       →    t=0.1s    →     t=0.5s        →    t=1.0s
                (5-10min TTL)
```

---

## Response Processing Pipeline

### 2.1 Complete Flow Diagram

```
Attestation Object (CBOR)
    ↓
[1] Base64URL Decode
    ↓
[2] CBOR Parse
    ├─ fmt: "none" | "fido-u2f" | "packed" | "android-safetynet" | etc
    ├─ attStmt: Attestation statement (public key + cert chain)
    └─ authData: Raw binary authenticator data
    ↓
[3] Extract & Parse authData Binary
    ├─ rpIdHash (32 bytes): SHA-256(relying party ID)
    ├─ flags (1 byte): UP(0x01) | UV(0x04) | AT(0x40) | ED(0x80)
    ├─ signCount (4 bytes): Counter for clone detection
    ├─ attested credential data (if AT flag set)
    │  ├─ aaguid (16 bytes): Authenticator GUID
    │  ├─ credentialIdLength (2 bytes): LE uint16
    │  ├─ credentialId: Encrypted opaque handle
    │  └─ publicKey (CBOR): Newly generated public key
    └─ extensions (if ED flag set): CBOR-encoded extension outputs
    ↓
[4] Decode & Parse clientDataJSON
    {
      "type": "webauthn.create" | "webauthn.get",
      "challenge": "base64url(...)",
      "origin": "https://example.com",
      "crossOrigin": false
    }
    ↓
[5] Validate Client Data
    ✓ type matches operation
    ✓ challenge === stored_challenge (Base64URL compare)
    ✓ origin === expected_origin (hostname match)
    ✓ crossOrigin === false (same-origin verification)
    ↓
[6] Validate Authenticator Data
    ✓ rpIdHash === SHA-256(RP ID)
    ✓ User Present flag set (UP = 0x01)
    ✓ User Verified flag set (UV = 0x04) if required
    ✓ signCount >= last_stored_signCount (cloning detection)
    ↓
[7] Verify Signature (Cryptographic)
    clientDataHash = SHA-256(UTF-8(clientDataJSON_string))
    Verify(publicKey, authData || clientDataHash, signature)
    ↓
[8] Post-Verification
    ✓ Increment stored signCount
    ✓ Mark credential as verified (first use)
    ✓ Create authenticated session
    ✓ Return 200 OK + auth token
```

### 2.2 Critical Data Transformations

#### Input Encoding: Base64URL

```
Standard Base64:     ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==
Base64URL:           ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_

Differences:
  + becomes -
  / becomes _
  Padding (=) is omitted

Example:
  Standard: "abc+/xyz=="
  Base64URL: "abc-_xyz"
```

Why Base64URL? URLs and JSON don't handle `+`, `/`, or trailing `=` well. Base64URL is URL-safe and JSON-safe.

#### CBOR Decoding

CBOR (Concise Binary Object Representation) is like binary JSON.

```
CBOR Example:
  {
    "fmt": "packed",
    "attStmt": {...},
    "authData": <hex bytes>
  }

CBOR Structure (map type 0xA3 = 3 pairs):
  A3              # map(3 items)
    63 666D74     # "fmt" (string, 3 bytes)
    66 7061636B6564  # "packed"
    67 617474 5374  # "attStmt"
    <CBOR map>
    ...
```

Libraries handle this; you call `cbor_decode()`. The critical part is extracting the three fields:

- `fmt`: Attestation format (determines how to validate)
- `attStmt`: The attestation statement (contains signature + optional cert chain)
- `authData`: Raw binary blob (parse manually using byte offsets)

#### Signature Verification: "Sign over authData || clientDataHash"

The authenticator signs a **concatenation**:

```
Data to sign = authData || clientDataHash
            = <raw authData bytes> + <SHA-256(clientDataJSON)>
            = 37 + 32 = 69 bytes (minimum)

authData is binary: [rpIdHash(32) | flags(1) | signCount(4) | ...]
clientDataHash is binary: [<32 bytes of SHA-256 output>]

The concatenation is what gets signed.
The signature is what's verified.
```

---

## Verification Checks

### 3.1 Replay Protection (Challenge Validation)

```javascript
// ❌ WRONG: String comparison
if (receivedChallenge !== storedChallenge) {
  // This fails because one is Base64URL, the other might be raw bytes
}

// ✓ CORRECT: Decode both, compare binary
const receivedBytes = base64URLToBytes(receivedChallenge);
const storedBytes = base64URLToBytes(storedChallenge);
if (!bytesEqual(receivedBytes, storedBytes)) {
  throw new Error("Challenge mismatch");
}
```

**Why this matters**: The challenge comes Base64URL-encoded from the browser. The stored challenge is also Base64URL. They must match EXACTLY (including padding if any). If you decode one and not the other, or compare the wrong encodings, you'll reject valid responses or accept forged ones.

### 3.2 Origin Validation (CORS Prevention)

```javascript
// From clientDataJSON
const received_origin = clientData.origin; // "https://app.example.com"

// From your config
const expected_origin = "https://app.example.com";

// ✓ CORRECT: Exact string match
if (received_origin !== expected_origin) {
  throw new Error("Origin mismatch (phishing/CSRF attempt)");
}

// ❌ WRONG: Ignoring subdomain differences
// "app.example.com" !== "example.com" — both are legitimate but different origins

// ❌ WRONG: Allowing HTTP (only HTTPS is secure)
// "http://example.com" !== "https://example.com"
```

The `origin` field is the browser's security boundary. It's what prevents a malicious site (evil.com) from hijacking your authentication.

### 3.3 RP ID Hash Verification (Domain Binding)

```
rpIdHash in authData = SHA-256("example.com")  [32 bytes]

Your server computes:
  computed_rpIdHash = SHA-256("example.com")

Check:
  if (authData.rpIdHash !== computed_rpIdHash) {
    throw new Error('RP ID mismatch');
  }

Why? An attacker can't register a credential for your domain on another domain.
Even if they steal the authenticator device, the credential won't work for
a different RP ID because the hash won't match.
```

### 3.4 Clone Detection (Sign Count)

```
First registration/login:
  signCount in authData = 0x00000001
  Stored in DB: sign_count = 1

Second login:
  signCount in authData = 0x00000002
  Stored in DB: sign_count = 1
  Check: 2 > 1 ✓ (increment as expected)
  Update: sign_count = 2

Attack scenario (device cloned):
  Attacker clones the authenticator
  Attacker logs in (sign_count increments on cloned device)
  Real user logs in on original (sign_count increments on original)

  Real user's device: sign_count = 5
  Attacker's device: sign_count = 2

  Real user tries to login:
    Receives 5, stored is 5 → SAME (should be > stored)
    ERROR: Possible clone detected

This detects cloning because each instance maintains a separate counter.
```

### 3.5 User Presence & Verification Flags

```
Flags byte structure:
  Bit 0 (0x01): User Present (UP)      - Button press / touch
  Bit 2 (0x04): User Verified (UV)     - Biometric / PIN
  Bit 6 (0x40): Attested Credential    - New credential in response
  Bit 7 (0x80): Extension Data         - Extensions included

Typical checks:
  ✓ UP must be set (user is physically present)
  ✓ UV should be set if requiring MFA
  ✓ AT only set during registration
```

---

## Code Implementation Examples

### 4.1 Challenge Generation (Node.js)

```javascript
const crypto = require("crypto");
const base64url = require("base64url");

// Generate challenge
function generateChallenge() {
  const challengeBytes = crypto.randomBytes(32);
  return base64url(challengeBytes);
}

// Store in session with expiration
function storeChallenge(sessionId, challenge, ttlSeconds = 300) {
  const expiresAt = Date.now() + ttlSeconds * 1000;

  // Redis example:
  redis.setex(
    `challenge:${sessionId}`,
    ttlSeconds,
    JSON.stringify({ challenge, expiresAt, type: "login" }),
  );

  // Database example:
  db.insertOne("challenges", {
    session_id: sessionId,
    challenge: challenge,
    created_at: new Date(),
    expires_at: new Date(expiresAt),
    type: "login",
    used: false,
  });
}

// Send to browser
app.post("/auth/initiate", (req, res) => {
  const sessionId = req.sessionID;
  const challenge = generateChallenge();
  storeChallenge(sessionId, challenge);

  res.json({
    challenge: challenge,
    timeout: 60000,
    userVerification: "preferred",
    // ... more options
  });
});
```

### 4.2 Response Processing (Python with py_webauthn)

```python
from webauthn import verify_authentication_response
from webauthn.helpers.structs import (
    AuthenticationCredential,
    UserVerificationRequirement,
)
import base64
import hashlib
from datetime import datetime, timedelta

def process_authentication_response(
    credential_json,
    session_id,
    expected_origin,
    expected_rp_id,
):
    """
    credential_json: {
      "id": "<base64url credential ID>",
      "rawId": "<base64url raw ID>",
      "response": {
        "clientDataJSON": "<base64url>",
        "authenticatorData": "<base64url>",
        "signature": "<base64url>"
      },
      "type": "public-key"
    }
    """

    try:
        # [1] Retrieve stored challenge
        stored_challenge = get_stored_challenge(session_id)
        if not stored_challenge:
            raise ValueError('Challenge expired or not found')

        # [2] Parse credential from browser
        credential = AuthenticationCredential.parse_raw(credential_json)

        # [3] Verify using library
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=stored_challenge.encode('utf-8'),  # Library expects bytes
            expected_origin=expected_origin,  # "https://app.example.com"
            expected_rp_id=expected_rp_id,     # "example.com"
            credential_public_key=get_public_key(credential.id),
            credential_current_sign_count=get_sign_count(credential.id),
            require_resident_key=False,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        # [4] Update sign count
        if verification.sign_count <= get_sign_count(credential.id):
            raise ValueError('Possible authenticator cloning detected')

        update_sign_count(credential.id, verification.sign_count)

        # [5] Create session
        mark_challenge_as_used(session_id)
        session_token = create_auth_session(
            user_id=get_user_id(credential.id),
            credential_id=credential.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
        )

        return {
            'status': 'ok',
            'session_token': session_token,
            'user': get_user_profile(credential.id),
        }

    except Exception as e:
        log_failed_attempt(session_id, str(e))
        raise
```

### 4.3 Manual Verification (if not using library)

```python
import hashlib
import cbor2
import base64
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def verify_fido2_response_manual(
    attestation_object_b64,
    client_data_json_b64,
    signature_b64,
    expected_challenge,
    expected_origin,
    expected_rp_id,
):
    """
    Low-level manual verification (educational; use a library in production)
    """

    # ===== [1] Decode Input =====
    attestation_bytes = base64.urlsafe_b64decode(
        attestation_object_b64 + '=' * (-len(attestation_object_b64) % 4)
    )
    attestation = cbor2.loads(attestation_bytes)

    # Extract fields
    fmt = attestation['fmt']  # "packed", "none", etc.
    att_stmt = attestation['attStmt']  # Contains signature + optional cert chain
    auth_data_bytes = attestation['authData']  # Raw binary

    client_data_json_bytes = base64.urlsafe_b64decode(
        client_data_json_b64 + '=' * (-len(client_data_json_b64) % 4)
    )
    client_data_json_str = client_data_json_bytes.decode('utf-8')

    signature_bytes = base64.urlsafe_b64decode(
        signature_b64 + '=' * (-len(signature_b64) % 4)
    )

    # ===== [2] Validate Client Data =====
    import json
    client_data = json.loads(client_data_json_str)

    assert client_data['type'] in ['webauthn.create', 'webauthn.get'], \
        f"Invalid type: {client_data['type']}"

    # Challenge comparison (Base64URL → bytes → compare)
    received_challenge = base64.urlsafe_b64decode(
        client_data['challenge'] + '=' * (-len(client_data['challenge']) % 4)
    )
    stored_challenge = base64.urlsafe_b64decode(
        expected_challenge + '=' * (-len(expected_challenge) % 4)
    )

    assert received_challenge == stored_challenge, "Challenge mismatch"
    assert client_data['origin'] == expected_origin, "Origin mismatch"
    assert client_data.get('crossOrigin') == False, "Cross-origin detected"

    # ===== [3] Parse Authenticator Data =====
    # authData structure:
    # rpIdHash (32 bytes) | flags (1 byte) | signCount (4 bytes) | [attested_cred_data] | [extensions]

    rp_id_hash = auth_data_bytes[0:32]
    flags_byte = auth_data_bytes[32]
    sign_count_bytes = auth_data_bytes[33:37]

    # Flags
    user_present = (flags_byte & 0x01) != 0
    user_verified = (flags_byte & 0x04) != 0
    attested_cred = (flags_byte & 0x40) != 0
    extension_data = (flags_byte & 0x80) != 0

    assert user_present, "User present flag not set"

    # Sign count
    sign_count = struct.unpack('>I', sign_count_bytes)[0]

    # ===== [4] Validate RP ID Hash =====
    expected_rp_id_hash = hashlib.sha256(expected_rp_id.encode()).digest()
    assert rp_id_hash == expected_rp_id_hash, "RP ID hash mismatch"

    # ===== [5] Verify Signature =====
    # Signature is computed over: authData || SHA-256(clientDataJSON)

    client_data_hash = hashlib.sha256(client_data_json_bytes).digest()
    signed_data = auth_data_bytes + client_data_hash

    # For "none" attestation (no signature), skip this
    # For other formats, verify the signature

    if fmt == 'packed' or fmt == 'fido-u2f':
        # Get public key from attestation (this is simplified)
        # In reality: parse from credential data or from cert chain
        # Here we assume it's provided separately
        public_key = get_public_key_from_storage()

        # Verify (ES256 example; other algorithms exist)
        public_key.verify(signature_bytes, signed_data, ec.ECDSA(hashes.SHA256()))

    # ===== [6] Success =====
    return {
        'valid': True,
        'sign_count': sign_count,
        'user_verified': user_verified,
    }
```

### 4.4 Express Middleware (Integration)

```javascript
const express = require("express");
const { verifyAuthenticationResponse } = require("@simplewebauthn/server");

app.post("/auth/verify", async (req, res) => {
  try {
    const { credential, sessionId } = req.body;

    // Retrieve stored challenge
    const storedChallenge = await redis.get(`challenge:${sessionId}`);
    if (!storedChallenge) {
      return res.status(400).json({
        error: "challenge_expired",
        message: "Authentication challenge has expired. Please start again.",
      });
    }

    // Verify response
    const verification = verifyAuthenticationResponse({
      credential,
      expectedChallenge: storedChallenge,
      expectedOrigin: "https://app.example.com",
      expectedRPID: "example.com",
      internalUserID: req.session.userId,
    });

    if (!verification.verified) {
      // Log failed attempt
      await db.collection("failed_attempts").insertOne({
        user_id: req.session.userId,
        timestamp: new Date(),
        reason: "signature_verification_failed",
        ip: req.ip,
      });

      return res.status(401).json({
        error: "verification_failed",
        message: "Credential verification failed.",
      });
    }

    // Check sign count for cloning
    const storedCredential = await db.collection("credentials").findOne({
      id: credential.id,
    });

    if (verification.signCount <= storedCredential.signCount) {
      await db.collection("security_alerts").insertOne({
        alert_type: "possible_cloning",
        credential_id: credential.id,
        user_id: req.session.userId,
        timestamp: new Date(),
        severity: "HIGH",
      });

      // Do NOT log in; alert security team
      return res.status(401).json({
        error: "cloning_detected",
        message: "This credential appears to have been cloned.",
      });
    }

    // Update sign count
    await db
      .collection("credentials")
      .updateOne(
        { id: credential.id },
        { $set: { signCount: verification.signCount } },
      );

    // Create session
    const user = await db.collection("users").findOne({
      credential_id: credential.id,
    });

    req.session.userId = user._id;
    req.session.authenticatedAt = new Date();

    // Clear challenge
    await redis.del(`challenge:${sessionId}`);

    res.json({
      status: "authenticated",
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
      },
      sessionToken: req.session.id,
    });
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(500).json({
      error: "internal_error",
      message: "An unexpected error occurred during verification.",
    });
  }
});
```

---

## Data Models & Storage

### 5.1 Database Schema

```sql
-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(255),
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  INDEX (email)
);

-- Registered credentials
CREATE TABLE credentials (
  id BYTEA PRIMARY KEY,                    -- base64url credential ID
  user_id UUID REFERENCES users(id),
  public_key BYTEA NOT NULL,               -- CBOR-encoded public key
  aaguid BYTEA,                            -- Authenticator GUID
  sign_count BIGINT DEFAULT 0,             -- Clone detection
  rp_id VARCHAR(255) NOT NULL,             -- Domain bound to
  transports VARCHAR(50) ARRAY,            -- ["usb", "ble", "nfc", "internal"]
  backup_eligible BOOLEAN DEFAULT FALSE,   -- Can backup credential
  backup_state BOOLEAN DEFAULT FALSE,      -- Currently backed up
  created_at TIMESTAMP,
  last_used TIMESTAMP,
  INDEX (user_id),
  INDEX (rp_id)
);

-- Challenge tracking
CREATE TABLE challenges (
  id UUID PRIMARY KEY,
  session_id VARCHAR(255),
  challenge BYTEA NOT NULL,                -- Raw challenge bytes (not Base64)
  type ENUM('registration', 'authentication'),
  created_at TIMESTAMP,
  expires_at TIMESTAMP,
  used BOOLEAN DEFAULT FALSE,
  used_at TIMESTAMP,
  ip_address INET,
  user_agent TEXT,
  INDEX (session_id),
  INDEX (expires_at)
);

-- Authentication attempts (audit trail)
CREATE TABLE auth_attempts (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  credential_id BYTEA REFERENCES credentials(id),
  status ENUM('success', 'failed_verification', 'challenge_mismatch', 'cloning_detected'),
  timestamp TIMESTAMP,
  ip_address INET,
  user_agent TEXT,
  error_message TEXT,
  INDEX (user_id),
  INDEX (timestamp)
);

-- Security alerts
CREATE TABLE security_alerts (
  id UUID PRIMARY KEY,
  alert_type ENUM('cloning_detected', 'replay_detected', 'origin_mismatch'),
  user_id UUID REFERENCES users(id),
  credential_id BYTEA REFERENCES credentials(id),
  severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
  timestamp TIMESTAMP,
  resolved BOOLEAN DEFAULT FALSE,
  investigation_notes TEXT,
  INDEX (user_id),
  INDEX (severity),
  INDEX (resolved)
);
```

### 5.2 Redis Cache Schema

```
Key: challenge:{sessionId}
TTL: 300 seconds (5 minutes)
Value: {
  "challenge": "base64url_string",
  "created_at": "2024-01-15T10:30:00Z",
  "type": "authentication"
}

Key: auth_session:{sessionId}
TTL: 3600 seconds (1 hour)
Value: {
  "user_id": "uuid",
  "credential_id": "base64url",
  "authenticated_at": "2024-01-15T10:31:00Z",
  "ip_address": "203.0.113.45",
  "last_activity": "2024-01-15T10:45:00Z"
}
```

---

## Security Considerations

### 6.1 Challenge Expiration

```
Why: A captured challenge should have a limited window of validity

Recommendations:
  - Registration challenges: 10 minutes
  - Authentication challenges: 5 minutes

If challenge expires:
  - User must start over
  - Browser will get an error from the authenticator
  - Backend will reject the response (challenge not found)

Implementation:
  Redis: setex('challenge:...', 300, value)
  DB: expires_at = NOW() + INTERVAL 5 MINUTES
      Cron job to delete expired challenges hourly
```

### 6.2 Preventing Replay Attacks

```
Attack: Attacker intercepts a valid response and replays it later

Prevention:
  1. Challenge is one-time use
     ✓ Mark challenge as "used" after first verification
     ✓ Reject any subsequent use of same challenge

  2. Challenge is bound to session
     ✓ Can't use challenge from different session
     ✓ Different users get different challenges

  3. Challenge is time-bound
     ✓ Old challenges expire
     ✓ Reduces window of opportunity

Implementation:
  After successful verification:
    UPDATE challenges SET used = TRUE, used_at = NOW() WHERE id = ?;

  On verification attempt:
    SELECT * FROM challenges WHERE id = ? AND used = FALSE AND expires_at > NOW();
    If 0 rows: REJECT ("Challenge already used or expired")
```

### 6.3 CSRF Protection via Origin

```
Attack: Site at evil.com tries to make user's browser authenticate to bank.com

Prevention:
  Browser sends Origin header (automatic, can't be spoofed)
  clientDataJSON includes origin
  Server validates: clientDataJSON.origin === expected_origin

Example:
  ✓ Correct: User at bank.com, origin = "https://bank.com"
  ✗ Phishing: User at bank-spoof.com, origin = "https://bank-spoof.com"
             (attacker can't fake the origin to be "https://bank.com")
  ✗ CSRF: evil.com tries to auth to bank.com
          User's browser sends origin = "https://evil.com"
          Bank.com rejects (origin mismatch)

Implementation:
  const expectedOrigin = process.env.ALLOWED_ORIGIN;  // Set in config

  if (clientData.origin !== expectedOrigin) {
    throw new Error(`Origin mismatch: got ${clientData.origin}, expected ${expectedOrigin}`);
  }
```

### 6.4 Clone Detection via Sign Count

```
Counter increments with each signature operation.

Threat Model:
  User registers with authenticator
  Attacker steals authenticator and clones it
  Both devices can now authenticate
  Attacker uses cloned device (signCount increments on clone)
  User uses real device (signCount increments on real)

Detection:
  Server tracks: signCount = 5

  Scenario 1: Attacker logs in first
    Attacker's device: signCount = 6
    Server updates: signCount = 6

  Scenario 2: Real user logs in
    Real device: signCount = 7
    Server expects: signCount >= 6
    Received 7 > 6: ✓ Valid

  Scenario 3: Attacker tries again
    Attacker's device: signCount = 6
    Server expects: signCount >= 7
    Received 6 < 7: ✗ CLONING DETECTED

Action:
  - Log security alert
  - Invalidate the credential
  - Force user to re-register
  - Notify user of suspicious activity
```

### 6.5 RP ID Hash Binding

```
RP ID = relying party identifier
For web: usually the domain (e.g., "example.com")
For native apps: app package name or bundle ID

In authData:
  rpIdHash = SHA-256(RP_ID) [32 bytes]

This hash is signed by the authenticator, so:
  - Authenticator commits to this specific RP ID
  - Credential can't be used for different domain
  - Even if attacker compromises the authenticator, they can't
    use the credential for a different site

Example:
  If you register on example.com:
    rpIdHash = SHA-256("example.com")

  If attacker tries to use credential on evil.com:
    rpIdHash would need = SHA-256("evil.com")
    But device signed with SHA-256("example.com")
    MISMATCH: Credential rejected
```

---

## Error Handling & Recovery

### 7.1 Common Error Scenarios

```
┌─────────────────────────────────────────────────────────────┐
│ Error Scenario              │ User Experience    │ Recovery  │
├─────────────────────────────────────────────────────────────┤
│ Challenge expired (5+ min)  │ "Try again"        │ Restart   │
│ Challenge mismatch          │ "Invalid response" │ Restart   │
│ Origin mismatch             │ "Wrong domain"     │ Check URL │
│ Signature verification fail │ "Auth failed"      │ Retry     │
│ Clone detected              │ "Security issue"   │ Re-reg    │
│ RP ID mismatch              │ "Incompatible"     │ Check dev │
│ Network error (no response) │ Timeout            │ Retry     │
│ Unsupported authenticator   │ "Device not ok"    │ Use USB   │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Structured Error Responses

```javascript
// ALWAYS return consistent error format

// Registration failure
{
  "success": false,
  "error": {
    "code": "CHALLENGE_EXPIRED",
    "message": "Your registration challenge has expired. Please start the registration process again.",
    "recoverable": true,  // User can retry
    "retry_after_seconds": 1
  }
}

// Authentication failure
{
  "success": false,
  "error": {
    "code": "SIGNATURE_VERIFICATION_FAILED",
    "message": "Your authenticator response could not be verified.",
    "recoverable": true,
    "retry_after_seconds": 5
  }
}

// Security incident (non-recoverable)
{
  "success": false,
  "error": {
    "code": "CLONING_DETECTED",
    "message": "We detected suspicious activity on your account. Please contact support.",
    "recoverable": false,  // User must re-register
    "contact": "security@example.com"
  }
}
```

### 7.3 Logging & Monitoring

```python
# Log structure for forensics
def log_auth_attempt(
    user_id: str,
    status: str,  # "success", "failed", "cloning_detected", etc.
    credential_id: str,
    error_code: Optional[str],
    ip_address: str,
    user_agent: str,
):
    """
    status can be:
      - "success": Authentication verified and session created
      - "challenge_expired": Challenge not found/expired
      - "challenge_mismatch": Challenge value doesn't match
      - "origin_mismatch": Origin doesn't match expected
      - "signature_failed": Cryptographic verification failed
      - "rp_id_mismatch": RP ID hash doesn't match
      - "clone_detected": Sign count decreased
      - "user_not_verified": UV flag not set (if required)
      - "user_not_present": UP flag not set
    """
    db.collection('auth_attempts').insert_one({
        'user_id': user_id,
        'status': status,
        'credential_id': credential_id,
        'error_code': error_code,
        'timestamp': datetime.utcnow(),
        'ip_address': ip_address,
        'user_agent': user_agent,
    })

    # Alert on suspicious patterns
    if status in ['clone_detected', 'origin_mismatch']:
        send_alert(
            f"Security incident for user {user_id}: {status}",
            severity='HIGH'
        )

# Monitor
def monitor_metrics():
    """
    Track these metrics:
      - Challenge generation rate
      - Challenge expiration rate
      - Successful auth rate
      - Failed verification rate
      - Clone detection rate
      - Average response time
    """
    total_challenges = db.challenges.count_documents({
        'created_at': {'$gte': one_hour_ago}
    })

    expired = db.challenges.count_documents({
        'created_at': {'$gte': one_hour_ago},
        'expires_at': {'$lt': now},
        'used': False
    })

    successful = db.auth_attempts.count_documents({
        'timestamp': {'$gte': one_hour_ago},
        'status': 'success'
    })

    return {
        'challenges_generated': total_challenges,
        'challenges_expired': expired,
        'successful_auth': successful,
        'expiration_rate': expired / total_challenges if total_challenges > 0 else 0,
    }
```

---

## Summary: Key Takeaways

1. **Challenge Generation**
   - Generate 32+ random bytes
   - Store with 5-10 minute expiration
   - Mark as used after first successful verification

2. **Response Processing**
   - Decode Base64URL inputs
   - Parse CBOR attestation object
   - Extract and validate authData binary structure
   - Verify challenge matches (replay protection)
   - Verify origin matches (CSRF prevention)
   - Verify RP ID hash matches (domain binding)
   - Verify signature cryptographically
   - Check sign count for cloning
   - Create authenticated session

3. **Security**
   - All comparisons must be timing-safe
   - All timestamps should be UTC
   - Log all auth attempts (audit trail)
   - Monitor for suspicious patterns
   - Rate-limit failed attempts
   - Invalidate cloned credentials

4. **Error Handling**
   - Return consistent error format
   - Distinguish between recoverable and non-recoverable errors
   - Don't leak internal details in error messages
   - Log everything for forensics

---

## Implementation Checklist

- [ ] Challenge generation with cryptographically secure randomness
- [ ] Challenge storage with expiration
- [ ] Base64URL encode/decode utilities
- [ ] CBOR parsing library integrated
- [ ] Client data JSON parsing
- [ ] Authenticator data binary parsing
- [ ] Challenge validation (replay protection)
- [ ] Origin validation (CSRF prevention)
- [ ] RP ID hash validation (domain binding)
- [ ] Sign count tracking (clone detection)
- [ ] Cryptographic signature verification
- [ ] Error logging and alerting
- [ ] Rate limiting on failed attempts
- [ ] Audit trail database
- [ ] Security monitoring dashboard
- [ ] User notification on suspicious activity
- [ ] Recovery procedures documented
- [ ] CORS headers configured correctly
- [ ] HTTPS enforced
- [ ] Input validation on all fields
