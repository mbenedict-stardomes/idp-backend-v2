import appInsights from 'applicationinsights';

/**
 * Get the App Insights client.
 * The SDK is initialized in start.js before this module loads.
 */
export function getClient() {
  return appInsights.defaultClient || null;
}

/**
 * Track a business journey step as a custom event in Application Insights.
 */
export function trackJourneyStep({
  journeyId,
  journeyInstanceId,
  journeyStep,
  correlationId,
  identityId = null,
  deviceId = null,
  success = true,
  durationMs = 0,
  properties = {},
}) {
  const client = getClient();
  if (!client) return;

  client.trackEvent({
    name: 'JourneyStep',
    properties: {
      journey_id: journeyId,
      journey_instance_id: journeyInstanceId || correlationId,
      journey_step: journeyStep,
      correlation_id: correlationId,
      identity_id: identityId,
      device_id: deviceId,
      success: String(success),
      duration_ms: String(durationMs),
      source: 'backend',
      ...properties,
    },
  });
}

/**
 * Track journey completion or abandonment.
 */
export function trackJourneyOutcome({
  journeyId,
  journeyInstanceId,
  outcome, // 'COMPLETED' | 'ABANDONED' | 'ERROR'
  lastStep,
  totalDurationMs = 0,
  correlationId = null,
  properties = {},
}) {
  const client = getClient();
  if (!client) return;

  client.trackEvent({
    name: 'JourneyOutcome',
    properties: {
      journey_id: journeyId,
      journey_instance_id: journeyInstanceId,
      outcome,
      last_step: lastStep,
      total_duration_ms: String(totalDurationMs),
      correlation_id: correlationId,
      source: 'backend',
      ...properties,
    },
  });
}
