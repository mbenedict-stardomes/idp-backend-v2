import sql from 'mssql';
import env from './env.js';

const config = {
  server: env.DB_SERVER,
  authentication: {
    type: 'azure-active-directory-default',
    options: {
      clientId: env.AZURE_CLIENT_ID,
    },
  },
  options: {
    database: env.DB_NAME,
    encrypt: true,
    trustServerCertificate: false,
  },
  pool: {
    max: 10,
    min: 1,
    idleTimeoutMillis: 30000,
  },
};

let pool;

export async function getPool() {
  if (!pool) {
    pool = await sql.connect(config);
  }
  return pool;
}

export async function closePool() {
  if (pool) {
    await pool.close();
    pool = null;
  }
}

export { sql };
