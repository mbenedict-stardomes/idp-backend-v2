import crypto from 'crypto';

// Simple JWT implementation (no external library needed)
// In production, consider using jsonwebtoken package with RS256

const ALGORITHM = 'HS256';

/**
 * Create a JWT token
 * @param {object} payload - Token claims
 * @param {string} secret - Signing secret
 * @param {number} expiresIn - Expiration time in seconds
 * @returns {string} JWT token
 */
export function createToken(payload, secret, expiresIn = 3600) {
  const header = { alg: ALGORITHM, typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  
  const claims = {
    ...payload,
    iat: now,
    exp: now + expiresIn,
  };

  const headerEncoded = base64UrlEncode(JSON.stringify(header));
  const payloadEncoded = base64UrlEncode(JSON.stringify(claims));
  const signature = sign(`${headerEncoded}.${payloadEncoded}`, secret);

  return `${headerEncoded}.${payloadEncoded}.${signature}`;
}

/**
 * Verify and decode a JWT token
 * @param {string} token - JWT token
 * @param {string} secret - Signing secret
 * @returns {object|null} Decoded payload or null if invalid
 */
export function verifyToken(token, secret) {
  try {
    const [headerEncoded, payloadEncoded, signatureEncoded] = token.split('.');
    
    if (!headerEncoded || !payloadEncoded || !signatureEncoded) {
      return null;
    }

    // Verify signature
    const expectedSignature = sign(`${headerEncoded}.${payloadEncoded}`, secret);
    if (expectedSignature !== signatureEncoded) {
      return null;
    }

    // Decode payload
    const payload = JSON.parse(base64UrlDecode(payloadEncoded));

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch (err) {
    console.error('Token verification failed:', err.message);
    return null;
  }
}

function sign(data, secret) {
  return base64UrlEncode(
    crypto.createHmac('sha256', secret).update(data).digest()
  );
}

function base64UrlEncode(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding
  base64 += '='.repeat((4 - (base64.length % 4)) % 4);
  return Buffer.from(base64, 'base64').toString();
}
