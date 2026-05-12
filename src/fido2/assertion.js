import crypto from 'crypto';
import { base64URLDecode, convertCOSEPublicKeyToDER, timingSafeEqual } from '../utils/fido2.js';
import { getPool, sql } from '../config/database.js';

export async function verifyFIDO2Assertion(assertion, avr, device) {
  // STEP 1 (B-AUTH-05a): Decode all Base64URL inputs to Buffers
  const authDataBuf = base64URLDecode(assertion.response.authenticatorData);
  const clientDataBuf = base64URLDecode(assertion.response.clientDataJSON);
  const sigBuf = base64URLDecode(assertion.response.signature);

  // STEP 2 (B-AUTH-05b): Parse clientDataJSON — verify type
  let clientData;
  try {
    clientData = JSON.parse(clientDataBuf.toString("utf-8"));
  } catch (e) {
    throw new Error("invalid_client_data");
  }
  
  if (clientData.type !== "webauthn.get") {
    throw new Error("invalid_client_data");
  }

  // STEP 3 (B-AUTH-05c): Challenge verification — anti-replay, timing-safe
  const receivedChallenge = base64URLDecode(clientData.challenge);
  const storedChallenge = base64URLDecode(avr.challenge);
  
  if (!timingSafeEqual(receivedChallenge, storedChallenge)) {
    throw new Error("challenge_mismatch");
  }

  // STEP 4 (B-AUTH-05d): Origin verification — anti-phishing
  if (clientData.origin !== "https://app.stardomes.ae") {
    // Audit log should capture FIDO2_ORIGIN_MISMATCH
    throw new Error("origin_mismatch");
  }
  if (clientData.crossOrigin === true) {
    throw new Error("origin_mismatch");
  }

  // STEP 5 (B-AUTH-05e & 05f): Parse authenticator data binary structure
  const rpIdHash = authDataBuf.slice(0, 32);
  const flags = authDataBuf[32];
  const signCount = authDataBuf.readUInt32BE(33);

  // STEP 6: RP ID hash verification
  const expectedRpIdHash = crypto.createHash("sha256").update("stardomes.ae").digest();
  if (!rpIdHash.equals(expectedRpIdHash)) {
    throw new Error("rp_id_mismatch");
  }

  // STEP 7: User presence (UP) and user verification (UV) flags
  const userPresent = (flags & 0x01) !== 0;
  const userVerified = (flags & 0x04) !== 0;
  if (!userPresent) throw new Error("user_not_present");
  if (!userVerified) throw new Error("user_not_verified"); // biometric required

  // STEP 8 (B-AUTH-05g & 05j): Clone detection via signature counter
  if (signCount <= device.signature_counter && signCount !== 0) {
    await handleCloneDetection(device);
    throw new Error("cloning_detected");
  }

  // STEP 9 (B-AUTH-05h): Cryptographic signature verification
  const clientDataHash = crypto.createHash("sha256").update(clientDataBuf).digest();
  const signedData = Buffer.concat([authDataBuf, clientDataHash]);
  
  const publicKeyKeyObject = convertCOSEPublicKeyToDER(device.fido2_public_key_cbor);
  
  const isValid = crypto.verify("sha256", signedData, publicKeyKeyObject, sigBuf);
  if (!isValid) throw new Error("invalid_signature");

  // STEP 10 (B-AUTH-05i): Update state
  await updateSignatureCounter(device.id, signCount);
  await markAVRApproved(avr.id, {
    signCount,
    sigBuf,
    authDataBuf,
    clientDataBuf,
  });

  return { verified: true, signCount };
}

async function handleCloneDetection(device) {
  const pool = await getPool();
  await pool.request()
    .input('id', sql.UniqueIdentifier, device.id)
    .query(`
      UPDATE idr_identity_device_registry 
      SET revoked = 1, revoked_at = SYSUTCDATETIME(), revocation_reason = 'POSSIBLE_CLONE_DETECTED' 
      WHERE id = @id
    `);
  
  // NOTE: B-AUTH-05j requires writing CRITICAL security event to sal_secure_audit_log
  // and publishing alert to Service Bus.
}

async function updateSignatureCounter(deviceId, newSignCount) {
  const pool = await getPool();
  await pool.request()
    .input('id', sql.UniqueIdentifier, deviceId)
    .input('sign_count', sql.BigInt, newSignCount)
    .query(`
      UPDATE idr_identity_device_registry 
      SET signature_counter = @sign_count, last_active = SYSUTCDATETIME(), successful_auth_count = successful_auth_count + 1 
      WHERE id = @id
    `);
}

async function markAVRApproved(avrId, data) {
  const pool = await getPool();
  await pool.request()
    .input('id', sql.UniqueIdentifier, avrId)
    .input('sign_count', sql.BigInt, data.signCount)
    .input('signature_data', sql.VarBinary(sql.MAX), data.sigBuf)
    .input('authenticator_data_raw', sql.VarBinary(sql.MAX), data.authDataBuf)
    .input('client_data_json', sql.NVarChar(sql.MAX), data.clientDataBuf.toString("utf-8"))
    .query(`
      UPDATE avr_authentication_validation_request 
      SET status = 'APPROVED', 
          validated_at = SYSUTCDATETIME(), 
          sign_count = @sign_count, 
          signature_data = @signature_data, 
          authenticator_data_raw = @authenticator_data_raw, 
          client_data_json = @client_data_json, 
          user_action = 'APPROVE' 
      WHERE id = @id
    `);
}
