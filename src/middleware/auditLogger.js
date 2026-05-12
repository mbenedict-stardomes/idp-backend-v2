import * as auditService from '../services/audit.service.js';

const ACTION_MAP = {
  'POST /v1/app/identity/register': 'IDENTITY_CREATED',
  'POST /v1/app/device/register': 'DEVICE_REGISTERED',
  'PATCH /v1/admin/identities/*/status': 'IDENTITY_STATUS_CHANGED',
  'POST /v1/admin/devices/*/revoke': 'DEVICE_REVOKED',
};

function matchRoute(method, path) {
  const key = `${method} ${path}`;
  for (const [pattern, action] of Object.entries(ACTION_MAP)) {
    const regex = new RegExp('^' + pattern.replace(/\*/g, '[^/]+') + '$');
    if (regex.test(key)) return action;
  }
  return null;
}

export function auditLog() {
  return (req, res, next) => {
    const originalJson = res.json.bind(res);

    res.json = (body) => {
      // Only audit successful write operations
      const action = matchRoute(req.method, req.route?.path ? `${req.baseUrl}${req.route.path}` : req.path);
      if (action && res.statusCode >= 200 && res.statusCode < 300) {
        auditService.appendEntry({
          actor_type: 'SYSTEM',
          actor_id: req.ip || 'unknown',
          action_type: `HTTP_${action}`,
          resource_type: 'API',
          resource_id: req.originalUrl,
          event_detail: { method: req.method, status: res.statusCode },
          correlation_id: req.correlationId,
        }).catch(err => console.error('[AUDIT] Failed to log:', err.message));
      }

      return originalJson(body);
    };

    next();
  };
}
