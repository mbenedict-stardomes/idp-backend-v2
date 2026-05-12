import { getPool, sql } from '../config/database.js';

export async function registerDevice({
  identity_id,
  device_permanent_id,
  device_model,
  os_type,
  os_version,
  device_public_key,
  attestation_object,
  attestation_format,
}) {
  const pool = await getPool();

  const result = await pool.request()
    .input('identity_id', sql.UniqueIdentifier, identity_id)
    .input('device_permanent_id', sql.NVarChar(255), device_permanent_id)
    .input('device_model', sql.NVarChar(255), device_model || null)
    .input('os_type', sql.VarChar(20), os_type || null)
    .input('os_version', sql.NVarChar(50), os_version || null)
    .input('device_public_key', sql.NVarChar(sql.MAX), device_public_key)
    .input('attestation_object', sql.VarBinary(sql.MAX), attestation_object ? Buffer.from(attestation_object, 'base64') : null)
    .input('attestation_format', sql.VarChar(20), attestation_format || null)
    .query(`
      INSERT INTO idr_identity_device_registry
        (identity_id, device_permanent_id, device_model, os_type, os_version,
         device_public_key, attestation_object, attestation_format)
      OUTPUT
        INSERTED.id,
        INSERTED.identity_id,
        INSERTED.device_permanent_id,
        INSERTED.device_model,
        INSERTED.os_type,
        INSERTED.os_version,
        INSERTED.is_trusted,
        INSERTED.registered_at
      VALUES
        (@identity_id, @device_permanent_id, @device_model, @os_type, @os_version,
         @device_public_key, @attestation_object, @attestation_format)
    `);

  return result.recordset[0];
}

export async function getDeviceStatus(id) {
  const pool = await getPool();

  const result = await pool.request()
    .input('id', sql.UniqueIdentifier, id)
    .query(`
      SELECT id, identity_id, device_permanent_id, device_model,
             os_type, os_version, is_trusted, registered_at,
             last_active, revoked_at, revocation_reason
      FROM idr_identity_device_registry
      WHERE id = @id
    `);

  return result.recordset[0] || null;
}

export async function listDevicesByIdentity(identityId) {
  const pool = await getPool();

  const result = await pool.request()
    .input('identity_id', sql.UniqueIdentifier, identityId)
    .query(`
      SELECT id, device_permanent_id, device_model, os_type, os_version,
             is_trusted, registered_at, last_active, revoked_at, revocation_reason
      FROM idr_identity_device_registry
      WHERE identity_id = @identity_id
      ORDER BY registered_at DESC
    `);

  return result.recordset;
}

export async function deleteDevice(id) {
  const pool = await getPool();
  await pool.request()
    .input('id', sql.UniqueIdentifier, id)
    .query(`DELETE FROM idr_identity_device_registry WHERE id = @id`);
}

export async function revokeDevice(id, reason) {
  const pool = await getPool();

  const result = await pool.request()
    .input('id', sql.UniqueIdentifier, id)
    .input('reason', sql.NVarChar(255), reason)
    .query(`
      UPDATE idr_identity_device_registry
      SET revoked_at = SYSUTCDATETIME(), revocation_reason = @reason
      OUTPUT
        INSERTED.id,
        INSERTED.revoked_at,
        INSERTED.revocation_reason
      WHERE id = @id AND revoked_at IS NULL
    `);

  return result.recordset[0] || null;
}

export async function updateLastActive(id) {
  const pool = await getPool();

  await pool.request()
    .input('id', sql.UniqueIdentifier, id)
    .query(`
      UPDATE idr_identity_device_registry
      SET last_active = SYSUTCDATETIME()
      WHERE id = @id
    `);
}
