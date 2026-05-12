import crypto from 'crypto';
import cbor from 'cbor';

export function base64URLEncode(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    buffer = Buffer.from(buffer);
  }
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

export function base64URLDecode(str) {
  const padded = str + '='.repeat((4 - str.length % 4) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64');
}

export function cborDecode(buffer) {
  return cbor.decodeFirstSync(buffer, { preferMap: true });
}

export function convertCOSEPublicKeyToDER(cosePublicKeyBuffer) {
  // Parse CBOR COSE EC P-256 key map
  const coseStruct = cbor.decodeFirstSync(cosePublicKeyBuffer);
  
  // For EC P-256: 
  // 1 (kty): 2 (EC2)
  // 3 (alg): -7 (ES256)
  // -1 (crv): 1 (P-256)
  // -2 (x): x-coordinate bytes
  // -3 (y): y-coordinate bytes

  const x = coseStruct.get(-2);
  const y = coseStruct.get(-3);
  
  if (!x || !y) {
    throw new Error('Invalid COSE public key format: missing coordinates');
  }

  // Construct uncompressed point
  const uncompressedPoint = Buffer.concat([Buffer.from([0x04]), x, y]);

  // Wrap in SubjectPublicKeyInfo DER structure with EC P-256 OID
  // OID for id-ecPublicKey: 1.2.840.10045.2.1
  // OID for prime256v1: 1.2.840.10045.3.1.7
  const derHex = `3059301306072a8648ce3d020106082a8648ce3d030107034200${uncompressedPoint.toString('hex')}`;
  
  return crypto.createPublicKey({
    key: Buffer.from(derHex, 'hex'),
    format: 'der',
    type: 'spki'
  });
}

export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
