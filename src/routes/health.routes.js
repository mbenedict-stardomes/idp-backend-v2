import { Router } from 'express';
import { getPool } from '../config/database.js';

const router = Router();

router.get('/health', async (_req, res) => {
  let dbStatus = 'disconnected';
  try {
    const pool = await getPool();
    const result = await pool.request().query('SELECT 1 AS ok');
    if (result.recordset[0].ok === 1) {
      dbStatus = 'connected';
    }
  } catch {
    dbStatus = 'error';
  }

  const healthy = dbStatus === 'connected';
  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'healthy' : 'degraded',
    version: '1.0.0',
    database: dbStatus,
    timestamp: new Date().toISOString(),
  });
});

export default router;
