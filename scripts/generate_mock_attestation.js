import crypto from 'crypto';
import cbor from 'cbor';

function generateMockAttestation(devicePermanentId) {
  // 1. Expected RP ID Hash
  const rpIdHash = crypto.createHash('sha256').update('stardomes.ae').digest();

  // 2. Flags: 0x41 (AT flag set = 0x40 | UP flag set = 0x01)
  const flags = Buffer.from([0x41]);

  // 3. Sign Count: 0
  const signCount = Buffer.alloc(4);
  signCount.writeUInt32BE(0, 0);

  // 4. AAGUID: 16 bytes (all zeros for mock)
  const aaguid = Buffer.alloc(16, 0);

  // 5. Credential ID
  const credentialId = Buffer.from(`cred_${devicePermanentId}`);
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(credentialId.length, 0);

  // 6. Credential Public Key (CBOR encoded COSE Key)
  // EC P-256 (alg -7)
  const coseKey = new Map([
    [1, 2], // kty: EC2
    [3, -7], // alg: ES256
    [-1, 1], // crv: P-256
    [-2, crypto.randomBytes(32)], // x
    [-3, crypto.randomBytes(32)]  // y
  ]);
  const credentialPublicKeyCbor = cbor.encode(coseKey);

  // Combine authData
  const authData = Buffer.concat([
    rpIdHash,
    flags,
    signCount,
    aaguid,
    credIdLen,
    credentialId,
    credentialPublicKeyCbor
  ]);

  // Create Attestation Object
  const attObj = new Map([
    ['fmt', 'none'],
    ['attStmt', new Map()],
    ['authData', authData]
  ]);

  const attestationBuffer = cbor.encode(attObj);
  const attestationBase64Url = attestationBuffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  console.log(JSON.stringify({
    mockCredentialId: credentialId.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
    attestationObject: attestationBase64Url
  }, null, 2));
}

generateMockAttestation('mock_device_123');
