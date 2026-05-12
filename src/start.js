/**
 * Entry point for the IdP Core Service.
 *
 * Telemetry is initialized by telemetry-init.cjs via --require flag
 * BEFORE any ESM modules load. This ensures applicationinsights can
 * monkey-patch http, mssql, etc. for auto-collection.
 *
 * See package.json: node --require ./src/telemetry-init.cjs src/start.js
 */
import './server.js';
