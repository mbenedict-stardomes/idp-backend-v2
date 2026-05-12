# Stardomes IdP Backend v2

## Objective & Summary

The Stardomes IdP Backend provides a secure, standards-based identity provider (IdP) platform for strong user authentication and authorization, leveraging FIDO2, OIDC, and CIBA protocols. It is designed to support high-assurance digital identity creation, device-based 2FA, and secure transaction approval for banking and fintech applications. The backend is built for cloud-native deployment on Azure, with robust cryptographic, audit, and messaging infrastructure.

**Key Objectives:**

- Enable digital identity creation and management with strong cryptographic guarantees
- Support FIDO2-based device enrollment, attestation, and authentication (biometric 2FA)
- Provide secure, standards-compliant OIDC and CIBA flows for third-party integrations
- Ensure end-to-end auditability, anti-replay, and resistance to spoofing and cloning attacks
- Integrate with national ID verification and external trust providers

---

## Architecture Overview

**Core Components:**

- **API Gateway:** Kong (mTLS termination, routing, rate limiting)
- **App Runtime:** Node.js (Azure Container Apps)
- **Database:** Azure SQL Server (see `OIDC_DDL_v2.sql`)
- **Message Bus:** Azure Service Bus (`sat.ingress`, `sat.uplink` topics)
- **Key Management:** Azure Key Vault, crypto key inventory
- **Audit Log:** Secure, hash-chained, optionally signed

**High-Level Flow:**

1. **Identity Creation:**
   - User identity is created with cryptographic methods, referencing national ID and verified attributes.
   - Unique subject identifiers and account numbers are generated and stored securely.
2. **Device Enrollment (FIDO2):**
   - User device generates a FIDO2 keypair (biometric-gated, e.g., FaceID/TouchID).
   - Device attestation is verified (Apple/Google root), and device is registered as trusted.
3. **2FA Authentication (CIBA/OIDC):**
   - Third-party (e.g., bank) initiates a CIBA flow; backend matches user, generates challenge, and relays via Service Bus to the user’s device.
   - Device responds with FIDO2 assertion; backend verifies full pipeline and issues tokens if successful.
4. **Token Issuance:**
   - Access and ID tokens are issued, DPoP/mTLS-bound, with pairwise subject identifiers and FIDO2 ACR claims.
5. **Audit & Security:**
   - All critical events are hash-chained in the audit log; device cloning, replay, and other attacks are detected and mitigated.

---

## Key Backend Constructs & Modules

- **Identity Management:** User creation, status updates, login hint resolution, admin listing.
- **National ID Verification:** Integration with government APIs, verification audit, IAL claims.
- **Device Registry:** Device enrollment, attestation, trust status, revocation, and active device management.
- **FIDO2 Challenge Manager:** Challenge generation, storage, consumption, and cleanup.
- **Client Management:** Client registration, authentication, user binding, and suspension.
- **OIDC/CIBA Auth Engine:** PAR/CIBA flows, FIDO2 assertion verification, token issuance, and session management.
- **Key Management:** Key pair generation, rotation, JWKS serving, and revocation.
- **Audit Log:** Hash-chained, tamper-evident event logging, FIDO2 event specialization.
- **Service Bus Integration:** CIBA request/response relay, push notification, dead-letter handling.
- **FIDO2 Utilities:** CBOR/COSE parsing, cryptographic helpers, timing-safe operations.

---

## Build & Deployment

- **Runtime:** Node.js (see `package.json`)
- **Build:**
  - Modules in `src/` (see `Build_Plan_v2.md` for details)
  - FIDO2 logic in `src/fido2/`
  - Device, identity, and client management in `src/services/`
- **Database:**
  - Schema in `OIDC_DDL_v2.sql`
  - 13+ tables for identity, device, client, audit, and FIDO2 challenge management
- **Deployment:**
  - Azure Container Apps
  - Kong API Gateway
  - Azure SQL, Service Bus, Key Vault

---

## References

- [FIDO2_Implementation_Guide.md](FIDO2_Implementation_Guide.md)
- [FIDO_Build_Prompt.md](FIDO_Build_Prompt.md)
- [Build_Plan_v2.md](Build_Plan_v2.md)
- [AUTH_TOKEN_SETUP.md](AUTH_TOKEN_SETUP.md)

---

For detailed API contracts, flows, and security considerations, see the referenced guides and build plans.
