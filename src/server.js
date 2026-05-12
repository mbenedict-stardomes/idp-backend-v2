import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import env from './config/env.js';
import { getPool } from './config/database.js';
import healthRoutes from './routes/health.routes.js';
import appRoutes from './routes/app.routes.js';
import adminRoutes from './routes/admin.routes.js';
import monitoringRoutes from './routes/monitoring.routes.js';

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Request correlation ID + journey context extraction
app.use((req, _res, next) => {
  req.correlationId = req.headers['x-correlation-id'] || crypto.randomUUID();

  // Journey context headers (sent by mobile app, propagated through Kong)
  req.journeyId = req.headers['x-journey-id'] || null;
  req.journeyInstanceId = req.headers['x-journey-instance'] || null;
  req.journeyStep = req.headers['x-journey-step'] || null;

  next();
});

// Routes
app.use(healthRoutes);
app.use(appRoutes);
app.use(adminRoutes);
app.use(monitoringRoutes);

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ error: 'not_found', error_description: 'The requested endpoint does not exist.' });
});

// Error handler
app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'server_error', error_description: 'An internal error occurred.' });
});

// Startup
async function start() {
  try {
    console.log(`[STARTUP] Connecting to database ${env.DB_SERVER}/${env.DB_NAME}...`);
    await getPool();
    console.log('[STARTUP] Database connected.');
  } catch (err) {
    console.error('[STARTUP] Database connection failed:', err.message);
    console.error('[STARTUP] Server will start but /health will report degraded.');
  }

  app.listen(env.PORT, () => {
    console.log(`[STARTUP] IdP Core listening on port ${env.PORT}`);
    console.log(`[STARTUP] Issuer: ${env.ISSUER_URL}`);
  });
}

start();
