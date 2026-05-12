import crypto from 'crypto';
import { cborDecode, base64URLDecode } from '../utils/fido2.js';
import { getPool, sql } from '../config/database.js';
import { verifyAppleAttestation } from './formats/apple.js';
import { verifyAndroidAttestation } from './formats/android-safetynet.js';

export async function verifyAttestation(deviceId, attestationObjectB64Url, clientDataJSONB64Url) {
  // B-DEV-02a: decodeCBORAttestation
  const attestationBuffer = base64URLDecode(attestationObjectB64Url);
  const attObj = cborDecode(attestationBuffer);
  
  const fmt = attObj.get('fmt');
  const attStmt = attObj.get('attStmt');
  const authData = attObj.get('authData');

  // B-DEV-02b: parseAuthenticatorData
  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = authData.readUInt32BE(33);
  
  // Extract credential data if AT flag (bit 6) is set
  let aaguid = null;
  let credentialId = null;
  let credentialPublicKeyCbor = null;

  if ((flags & 0x40) !== 0) {
    aaguid = authData.slice(37, 53);
    const credIdLen = authData.readUInt16BE(53);
    credentialId = authData.slice(55, 55 + credIdLen);
    credentialPublicKeyCbor = authData.slice(55 + credIdLen);
  } else {
    throw new Error('attestation_verification_failed');
  }

  // B-DEV-02c: verifyRpIdHash
  const expectedRpIdHash = crypto.createHash('sha256').update('stardomes.ae').digest();
  if (!rpIdHash.equals(expectedRpIdHash)) {
    throw new Error('rp_id_mismatch');
  }

  // B-DEV-02d: verifyAttestationFormat
  let jailbroken = false;
  if (fmt === 'apple') {
    const result = await verifyAppleAttestation(attStmt, authData);
    jailbroken = result.jailbroken;
  } else if (fmt === 'android-safetynet') {
    const result = await verifyAndroidAttestation(attStmt, authData);
    jailbroken = result.jailbroken;
  } else if (fmt === 'none') {
    // skip cert verification
  } else {
    throw new Error('attestation_verification_failed');
  }

  if (jailbroken) {
    throw new Error('device_compromised');
  }

  // B-DEV-02g & B-DEV-02h: extractAndStorePublicKey & setDeviceTrusted
  const pool = await getPool();
  await pool.request()
    .input('id', sql.UniqueIdentifier, deviceId)
    .input('fido2_public_key_cbor', sql.VarBinary(sql.MAX), credentialPublicKeyCbor)
    .input('fido2_credential_id', sql.NVarChar(255), credentialId.toString('base64url'))
    .input('aaguid', sql.UniqueIdentifier, aaguid ? aaguid.toString('hex').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5') : null)
    .input('attestation_format', sql.VarChar(50), fmt)
    .query(`
      UPDATE idr_identity_device_registry 
      SET 
        is_trusted = 1, 
        attestation_verified = 1, 
        signature_counter = 0,
        biometric_enrolled = 1,
        fido2_public_key_cbor = @fido2_public_key_cbor,
        fido2_credential_id = @fido2_credential_id,
        aaguid = @aaguid,
        attestation_format = @attestation_format
      WHERE id = @id
    `);

  return { verified: true, credentialId: credentialId.toString('base64url') };
}
