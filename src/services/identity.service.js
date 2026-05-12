import { getPool, sql } from '../config/database.js';
import { v4 as uuidv4 } from 'uuid';

export async function createIdentity({ display_name, email, phone }) {
  const pool = await getPool();
  const subjectIdentifier = `IDP-${uuidv4()}`;

  const result = await pool.request()
    .input('subject_identifier', sql.NVarChar(255), subjectIdentifier)
    .input('display_name', sql.NVarChar(255), display_name || null)
    .input('email', sql.NVarChar(320), email || null)
    .input('phone', sql.NVarChar(50), phone || null)
    .query(`
      INSERT INTO ic_identity_core
        (subject_identifier, display_name, email, phone)
      OUTPUT
        INSERTED.id,
        INSERTED.subject_identifier,
        INSERTED.display_name,
        INSERTED.email,
        INSERTED.phone,
        INSERTED.identity_status,
        INSERTED.created_at
      VALUES
        (@subject_identifier, @display_name, @email, @phone)
    `);

  return result.recordset[0];
}

export async function getIdentityById(id) {
  const pool = await getPool();

  const result = await pool.request()
    .input('id', sql.UniqueIdentifier, id)
    .query(`
      SELECT id, subject_identifier, display_name, email, phone,
             identity_status, created_at, updated_at
      FROM ic_identity_core
      WHERE id = @id
    `);

  return result.recordset[0] || null;
}

export async function getIdentityBySubject(subjectIdentifier) {
  const pool = await getPool();

  const result = await pool.request()
    .input('subject_identifier', sql.NVarChar(255), subjectIdentifier)
    .query(`
      SELECT id, subject_identifier, display_name, email, phone,
             identity_status, created_at, updated_at
      FROM ic_identity_core
      WHERE subject_identifier = @subject_identifier
    `);

  return result.recordset[0] || null;
}

export async function searchIdentities({ q, status, limit = 50, offset = 0 }) {
  const pool = await getPool();
  const request = pool.request();

  let where = '1=1';

  if (q) {
    request.input('q', sql.NVarChar(255), `%${q}%`);
    where += ` AND (subject_identifier LIKE @q OR display_name LIKE @q OR email LIKE @q OR phone LIKE @q)`;
  }

  if (status) {
    request.input('status', sql.VarChar(20), status);
    where += ' AND identity_status = @status';
  }

  request.input('limit', sql.Int, limit);
  request.input('offset', sql.Int, offset);

  const result = await request.query(`
    SELECT id, subject_identifier, display_name, email, phone,
           identity_status, created_at, updated_at
    FROM ic_identity_core
    WHERE ${where}
    ORDER BY created_at DESC
    OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY
  `);

  return result.recordset;
}

export async function updateIdentityStatus(id, status) {
  const pool = await getPool();

  const result = await pool.request()
    .input('id', sql.UniqueIdentifier, id)
    .input('status', sql.VarChar(20), status)
    .query(`
      UPDATE ic_identity_core
      SET identity_status = @status, updated_at = SYSUTCDATETIME()
      OUTPUT
        INSERTED.id,
        INSERTED.subject_identifier,
        INSERTED.identity_status,
        INSERTED.updated_at
      WHERE id = @id
    `);

  return result.recordset[0] || null;
}
