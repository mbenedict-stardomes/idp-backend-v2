// src/workers/deadletter.worker.js
import * as auditService from '../services/audit.service.js';

export async function processDeadLetterMessage(message) {
  // Extract reason for dead letter
  const reason = message.deadLetterReason;

  if (reason === 'POSSIBLE_CLONE_DETECTED') {
    // Clone detection alerting
    console.error('CRITICAL ALARM: Possible device clone detected! Device ID:', message.deviceId);
    
    // Log to secure audit
    await auditService.appendEntry({
      actor_type: 'SYSTEM',
      actor_id: 'deadletter_worker',
      action_type: 'CLONE_DETECTED',
      resource_type: 'DEVICE',
      resource_id: message.deviceId,
      event_detail: { message: 'Authenticator clone detected based on signature counter' },
    });

    // In a real system, publish to security ops channel, trigger PagerDuty etc.
  }
}
