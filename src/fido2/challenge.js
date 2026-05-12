import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { getPool, sql } from '../config/database.js';
import { base64URLEncode } from '../utils/fido2.js';

export async function generateRegistrationChallenge() {
  const challengeBytes = crypto.randomBytes(32);
  const challengeB64Url = base64URLEncode(challengeBytes);
  const sessionId = uuidv4();
  
  // TTL = 600s for registration
  await storeChallenge({
    sessionId,
    challengeBytes,
    challengeB64Url,
    type: 'registration',
    identityId: null,
    avrId: null,
    expiresInMs: 600000
  });

  return {
    session_id: sessionId,
    challenge: challengeB64Url,
    timeout: 600000
  };
}

export async function generateAuthenticationChallenge(avrId, identityId) {
  const challengeBytes = crypto.randomBytes(32);
  const challengeB64Url = base64URLEncode(challengeBytes);
  const sessionId = uuidv4();

  // TTL = 300s for authentication
  await storeChallenge({
    sessionId,
    challengeBytes,
    challengeB64Url,
    type: 'authentication',
    identityId,
    avrId,
    expiresInMs: 300000
  });

  return {
    session_id: sessionId,
    challenge: challengeB64Url,
    timeout: 300000
  };
}

export async function storeChallenge({ sessionId, challengeBytes, challengeB64Url, type, identityId, avrId, expiresInMs, ipAddress = null, userAgent = null }) {
  const pool = await getPool();
  
  const expiresAt = new Date(Date.now() + expiresInMs);

  await pool.request()
    .input('session_id', sql.NVarChar(255), sessionId)
    .input('challenge_type', sql.VarChar(20), type)
    .input('identity_id', sql.UniqueIdentifier, identityId)
    .input('avr_id', sql.UniqueIdentifier, avrId)
    .input('challenge_bytes', sql.VarBinary(64), challengeBytes)
    .input('challenge_b64url', sql.NVarChar(255), challengeB64Url)
    .input('ip_address', sql.NVarChar(45), ipAddress)
    .input('user_agent', sql.NVarChar(sql.MAX), userAgent)
    .input('expires_at', sql.DateTime2, expiresAt)
    .query(`
      INSERT INTO fcs_fido2_challenge_store (
        session_id, challenge_type, identity_id, avr_id,
        challenge_bytes, challenge_b64url,
        ip_address, user_agent, expires_at
      ) VALUES (
        @session_id, @challenge_type, @identity_id, @avr_id,
        @challenge_bytes, @challenge_b64url,
        @ip_address, @user_agent, @expires_at
      )
    `);
}

export async function retrieveAndConsumeChallenge(sessionId) {
  const pool = await getPool();

  const selectResult = await pool.request()
    .input('session_id', sql.NVarChar(255), sessionId)
    .query(`
      SELECT TOP 1 id, challenge_bytes, challenge_b64url, challenge_type, expires_at 
      FROM fcs_fido2_challenge_store 
      WHERE session_id = @session_id AND consumed = 0 AND expires_at > SYSUTCDATETIME()
    `);

  const challengeRecord = selectResult.recordset[0];
  if (!challengeRecord) {
    throw new Error('challenge_expired');
  }

  const updateResult = await pool.request()
    .input('id', sql.UniqueIdentifier, challengeRecord.id)
    .query(`
      UPDATE fcs_fido2_challenge_store 
      SET consumed = 1, consumed_at = SYSUTCDATETIME() 
      WHERE id = @id AND consumed = 0
    `);

  if (updateResult.rowsAffected[0] === 0) {
    throw new Error('challenge_expired');
  }

  return challengeRecord;
}

export async function cleanExpiredChallenges() {
  const pool = await getPool();
  await pool.request().query(`
    DELETE FROM fcs_fido2_challenge_store WHERE expires_at < SYSUTCDATETIME()
  `);
}
