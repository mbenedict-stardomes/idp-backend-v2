import { getPool, sql } from '../config/database.js';
import { createToken, verifyToken } from '../utils/jwt.js';
import env from '../config/env.js';

const TOKEN_SECRET = env.AUTH_TOKEN_SECRET || 'default-secret-change-me';
const TOKEN_EXPIRY = parseInt(env.AUTH_TOKEN_EXPIRY_SECONDS || '3600', 10);

/**
 * Get a service account by client_id
 * @param {string} clientId - Service account client_id
 * @returns {object|null} Service account or null
 */
export async function getServiceAccount(clientId) {
  const pool = await getPool();

  const result = await pool.request()
    .input('client_id', sql.NVarChar(255), clientId)
    .query(`
      SELECT 
        id,
        client_id,
        account_name,
        account_status,
        scopes,
        created_at
      FROM sa_service_accounts
      WHERE client_id = @client_id
    `);

  return result.recordset[0] || null;
}

/**
 * Exchange client_id for an access token
 * @param {string} clientId - Service account client_id
 * @returns {string|null} JWT access token or null if account not found/inactive
 */
export async function issueAccessToken(clientId) {
  try {
    const account = await getServiceAccount(clientId);

    if (!account) {
      console.warn(`[AUTH] Service account not found: ${clientId}`);
      return null;
    }

    if (account.account_status !== 'ACTIVE') {
      console.warn(`[AUTH] Service account is ${account.account_status}: ${clientId}`);
      return null;
    }

    // Parse scopes
    let scopes = [];
    try {
      scopes = account.scopes ? JSON.parse(account.scopes) : [];
    } catch (err) {
      console.warn(`[AUTH] Failed to parse scopes for ${clientId}`);
    }

    // Create JWT token
    const token = createToken(
      {
        sub: account.id,
        client_id: clientId,
        scope: scopes.join(' '),
        type: 'service',
      },
      TOKEN_SECRET,
      TOKEN_EXPIRY
    );

    return token;
  } catch (err) {
    console.error('[AUTH] Token issuance failed:', err.message);
    return null;
  }
}

/**
 * Verify an access token (for middleware)
 * @param {string} token - JWT access token
 * @returns {object|null} Decoded token or null if invalid
 */
export function verifyAccessToken(token) {
  return verifyToken(token, TOKEN_SECRET);
}

/**
 * Extract bearer token from Authorization header
 * @param {string} authHeader - Authorization header value
 * @returns {string|null} Token or null
 */
export function extractBearerToken(authHeader) {
  if (!authHeader || typeof authHeader !== 'string') {
    return null;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }

  return parts[1];
}
