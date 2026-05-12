import { createHash } from 'crypto';

const GENESIS_HASH = createHash('sha384').update('GENESIS').digest('hex');

export function computePayloadHash(eventDetail) {
  const canonical = typeof eventDetail === 'string' ? eventDetail : JSON.stringify(eventDetail);
  return createHash('sha384').update(canonical).digest('hex');
}

export async function getPreviousRowHash(pool) {
  const result = await pool.request().query(
    'SELECT TOP 1 payload_hash FROM sal_secure_audit_log ORDER BY sequence_id DESC'
  );
  if (result.recordset.length === 0) {
    return GENESIS_HASH;
  }
  return result.recordset[0].payload_hash;
}
