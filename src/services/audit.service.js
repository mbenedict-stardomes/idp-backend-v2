import { getPool, sql } from '../config/database.js';
import { computePayloadHash, getPreviousRowHash } from '../utils/hashchain.js';

export async function appendEntry({
  actor_type,
  actor_id,
  action_type,
  resource_type = null,
  resource_id = null,
  event_detail = null,
  correlation_id = null,
}) {
  const pool = await getPool();

  const detailString = event_detail ? JSON.stringify(event_detail) : '{}';
  const payloadHash = computePayloadHash(detailString);
  const previousRowHash = await getPreviousRowHash(pool);

  const result = await pool.request()
    .input('actor_type', sql.VarChar(20), actor_type)
    .input('actor_id', sql.NVarChar(255), actor_id)
    .input('action_type', sql.NVarChar(100), action_type)
    .input('resource_type', sql.NVarChar(100), resource_type)
    .input('resource_id', sql.NVarChar(255), resource_id)
    .input('event_detail', sql.NVarChar(sql.MAX), detailString)
    .input('payload_hash', sql.NVarChar(128), payloadHash)
    .input('previous_row_hash', sql.NVarChar(128), previousRowHash)
    .input('correlation_id', sql.NVarChar(255), correlation_id)
    .query(`
      INSERT INTO sal_secure_audit_log
        (actor_type, actor_id, action_type, resource_type, resource_id,
         event_detail, payload_hash, previous_row_hash, correlation_id)
      OUTPUT INSERTED.sequence_id, INSERTED.event_uuid, INSERTED.created_at
      VALUES
        (@actor_type, @actor_id, @action_type, @resource_type, @resource_id,
         @event_detail, @payload_hash, @previous_row_hash, @correlation_id)
    `);

  return result.recordset[0];
}
