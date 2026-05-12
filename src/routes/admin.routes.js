import { Router } from 'express';
import * as identityService from '../services/identity.service.js';
import * as deviceService from '../services/device.service.js';
import * as auditService from '../services/audit.service.js';
import * as authService from '../services/auth.service.js';
import { trackJourneyStep } from '../config/telemetry.js';

const router = Router();

// ──────────────────────────────────────────────
// Authentication & Token Exchange
// ──────────────────────────────────────────────

/**
 * POST /v1/admin/auth/token
 * Exchange service account client_id for JWT access token
 * No authentication required (public endpoint for token exchange)
 */
router.post('/v1/admin/auth/token', async (req, res) => {
  try {
    const { client_id } = req.body;

    if (!client_id || typeof client_id !== 'string') {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'client_id is required and must be a string',
      });
    }

    const token = await authService.issueAccessToken(client_id);

    if (!token) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'The provided client_id is invalid or inactive',
      });
    }

    // Token issued successfully
    res.json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: parseInt(process.env.AUTH_TOKEN_EXPIRY_SECONDS || '3600', 10),
    });
  } catch (err) {
    console.error('[AUTH] Token issuance error:', err.message);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Failed to issue access token',
    });
  }
});

// ──────────────────────────────────────────────
// Authentication Middleware (optional strict mode)
// ──────────────────────────────────────────────
// Uncomment to enforce bearer token on all admin endpoints:
// router.use((req, res, next) => {
//   const authHeader = req.headers['authorization'];
//   const token = authService.extractBearerToken(authHeader);
//   if (!token) {
//     return res.status(401).json({
//       error: 'unauthorized',
//       error_description: 'Missing or invalid Authorization header',
//     });
//   }
//   const payload = authService.verifyAccessToken(token);
//   if (!payload) {
//     return res.status(401).json({
//       error: 'unauthorized',
//       error_description: 'Invalid or expired access token',
//     });
//   }
//   req.service = payload;
//   next();
// });

// ──────────────────────────────────────────────
// Identity Management
// ──────────────────────────────────────────────

router.get('/v1/admin/identities', async (req, res) => {
  try {
    const { q, status, limit, offset } = req.query;
    const identities = await identityService.searchIdentities({
      q,
      status,
      limit: parseInt(limit, 10) || 50,
      offset: parseInt(offset, 10) || 0,
    });
    res.json({ identities, count: identities.length });
  } catch (err) {
    console.error('[ADMIN] identities error:', err.message);
    res.status(500).json({ error: 'server_error', error_description: 'Failed to search identities.' });
  }
});

router.get('/v1/admin/identities/:id', async (req, res) => {
  try {
    const identity = await identityService.getIdentityById(req.params.id);
    if (!identity) {
      return res.status(404).json({ error: 'not_found', error_description: 'Identity not found.' });
    }
    res.json(identity);
  } catch (err) {
    console.error('[ADMIN] identities/:id error:', err.message);
    res.status(500).json({ error: 'server_error', error_description: 'Failed to fetch identity.' });
  }
});

router.patch('/v1/admin/identities/:id/status', async (req, res) => {
  try {
    const { status } = req.body;
    const valid = ['ACTIVE', 'LOCKED', 'SUSPENDED', 'REVOKED'];

    if (!status || !valid.includes(status)) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: `status must be one of: ${valid.join(', ')}`,
      });
    }

    const updated = await identityService.updateIdentityStatus(req.params.id, status);
    if (!updated) {
      return res.status(404).json({ error: 'not_found', error_description: 'Identity not found.' });
    }

    await auditService.appendEntry({
      actor_type: 'ADMIN',
      actor_id: 'admin',
      action_type: 'IDENTITY_STATUS_CHANGED',
      resource_type: 'IDENTITY',
      resource_id: req.params.id,
      event_detail: { new_status: status },
      correlation_id: req.correlationId,
    });

    res.json(updated);
  } catch (err) {
    console.error('[ADMIN] identities/:id/status error:', err.message);
    res.status(500).json({ error: 'server_error', error_description: 'Failed to update identity status.' });
  }
});

// ──────────────────────────────────────────────
// Device Management
// ──────────────────────────────────────────────

router.get('/v1/admin/identities/:id/devices', async (req, res) => {
  try {
    const devices = await deviceService.listDevicesByIdentity(req.params.id);
    res.json({ devices, count: devices.length });
  } catch (err) {
    console.error('[ADMIN] identities/:id/devices error:', err.message);
    res.status(500).json({ error: 'server_error', error_description: 'Failed to list devices.' });
  }
});

router.post('/v1/admin/devices/:id/revoke', async (req, res) => {
  const startTime = Date.now();
  try {
    const { reason } = req.body;

    if (!reason) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'reason is required (e.g., DEVICE_LOST, COMPROMISED, REPLACED).',
      });
    }

    const revoked = await deviceService.revokeDevice(req.params.id, reason);
    if (!revoked) {
      return res.status(404).json({
        error: 'not_found',
        error_description: 'Device not found or already revoked.',
      });
    }

    await auditService.appendEntry({
      actor_type: 'ADMIN',
      actor_id: 'admin',
      action_type: 'DEVICE_REVOKED',
      resource_type: 'DEVICE',
      resource_id: req.params.id,
      event_detail: { reason },
      correlation_id: req.correlationId,
    });

    trackJourneyStep({
      journeyId: req.journeyId || 'FLOW_ACCOUNT_MANAGEMENT',
      journeyInstanceId: req.journeyInstanceId,
      journeyStep: 'DEVICE_UNBIND',
      correlationId: req.correlationId,
      deviceId: req.params.id,
      success: true,
      durationMs: Date.now() - startTime,
      properties: { reason },
    });

    res.json(revoked);
  } catch (err) {
    console.error('[ADMIN] devices/:id/revoke error:', err.message);
    res.status(500).json({ error: 'server_error', error_description: 'Failed to revoke device.' });
  }
});

export default router;
