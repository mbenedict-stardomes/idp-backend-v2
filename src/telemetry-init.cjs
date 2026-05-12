/**
 * CommonJS telemetry initializer.
 *
 * Loaded via: node --require ./src/telemetry-init.cjs src/start.js
 *
 * This MUST be CommonJS (.cjs) because applicationinsights v3 uses
 * require() monkey-patching for auto-collection of HTTP requests and
 * SQL dependencies. ESM import() bypasses these patches entirely.
 *
 * See: https://github.com/microsoft/ApplicationInsights-node.js/issues/1354
 */
const appInsights = require('applicationinsights');

const connStr = process.env.APP_INSIGHTS_CONNECTION_STRING || '';

if (connStr && connStr !== 'ai-iot-test') {
  appInsights.setup(connStr)
    .setAutoDependencyCorrelation(true)
    .setAutoCollectRequests(true)
    .setAutoCollectPerformance(true, true)
    .setAutoCollectExceptions(true)
    .setAutoCollectDependencies(true)
    .setAutoCollectConsole(true, true)
    .setSendLiveMetrics(true)
    .start();

  const client = appInsights.defaultClient;
  client.context.tags[client.context.keys.cloudRole] = 'idp-core-backend';
  client.context.tags[client.context.keys.cloudRoleInstance] =
    process.env.CONTAINER_APP_REVISION || 'local';

  console.log('[TELEMETRY] Application Insights initialized (CJS pre-loader).');
} else {
  console.warn('[TELEMETRY] APP_INSIGHTS_CONNECTION_STRING not set. Telemetry disabled.');
}
