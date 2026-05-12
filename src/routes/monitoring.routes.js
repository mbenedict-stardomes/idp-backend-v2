import { Router } from 'express';
import {
  queryJourneyFunnel,
  queryStepPerformance,
  queryStepErrors,
  queryHealthOverview,
} from '../services/monitoring.service.js';

const router = Router();

const VALID_TIME_RANGES = ['1h', '4h', '6h', '12h', '24h', '7d', '30d'];
const VALID_JOURNEYS = [
  'FLOW_ONBOARD_REGISTRATION',
  'FLOW_AUTH_CHALLENGE_APPROVAL',
  'FLOW_ACCOUNT_MANAGEMENT',
];

function validateTimeRange(val) {
  return VALID_TIME_RANGES.includes(val) ? val : '24h';
}

// ─── Test Endpoint (accepts optional custom KQL query) ───

router.get('/v1/admin/monitoring/test', async (req, res) => {
  try {
    const { DefaultAzureCredential } = await import('@azure/identity');
    const { LogsQueryClient } = await import('@azure/monitor-query-logs');
    const env = (await import('../config/env.js')).default;

    const kql = req.query.kql || 'AppRequests | take 1';
    const duration = req.query.duration || 'PT1H';

    const credential = new DefaultAzureCredential(
      env.AZURE_CLIENT_ID ? { managedIdentityClientId: env.AZURE_CLIENT_ID } : undefined
    );
    const client = new LogsQueryClient(credential);

    console.log(`[MONITORING] test query: kql=${kql.substring(0, 100)}... duration=${duration}`);

    const result = await client.queryWorkspace(
      env.LOG_ANALYTICS_WORKSPACE_ID,
      kql,
      { duration }
    );

    const columns = result.tables?.[0]?.columnDescriptors?.map(c => c.name) || [];
    const rows = result.tables?.[0]?.rows?.slice(0, 5) || [];

    res.json({
      status: result.status,
      workspaceId: env.LOG_ANALYTICS_WORKSPACE_ID,
      tables: result.tables?.length || 0,
      columns,
      rowCount: result.tables?.[0]?.rows?.length || 0,
      sampleRows: rows,
    });
  } catch (err) {
    console.error('[MONITORING] test error:', err);
    res.status(500).json({
      error: err.name,
      message: err.message,
      code: err.code,
      statusCode: err.statusCode,
      details: err.details || null,
    });
  }
});

// ─── Diagnostic Endpoint (test progressively complex queries) ───

router.get('/v1/admin/monitoring/diagnose', async (req, res) => {
  try {
    const { DefaultAzureCredential } = await import('@azure/identity');
    const { LogsQueryClient } = await import('@azure/monitor-query-logs');
    const env = (await import('../config/env.js')).default;

    const credential = new DefaultAzureCredential(
      env.AZURE_CLIENT_ID ? { managedIdentityClientId: env.AZURE_CLIENT_ID } : undefined
    );
    const client = new LogsQueryClient(credential);
    const wsId = env.LOG_ANALYTICS_WORKSPACE_ID;

    const tests = [
      { name: 'simple_take', kql: 'AppRequests | take 1', duration: 'PT1H' },
      { name: 'simple_take_6h', kql: 'AppRequests | take 1', duration: 'PT6H' },
      { name: 'summarize_count', kql: 'AppRequests | summarize count()', duration: 'PT1H' },
      { name: 'summarize_bin', kql: 'AppRequests | summarize count() by bin(TimeGenerated, 5m) | take 5', duration: 'PT1H' },
      { name: 'where_filter', kql: 'AppRequests | where AppRoleName != "" | take 1', duration: 'PT1H' },
      { name: 'overview_simple', kql: 'AppRequests | summarize request_count = count(), error_count = countif(toint(ResultCode) >= 400) by bin(TimeGenerated, 5m) | sort by TimeGenerated asc | take 5', duration: 'PT1H' },
      { name: 'overview_full', kql: 'AppRequests | summarize request_count = count(), error_count = countif(toint(ResultCode) >= 400), avg_duration_ms = round(avg(DurationMs), 0), p95_duration_ms = round(percentile(DurationMs, 95), 0) by bin(TimeGenerated, 5m) | extend error_rate_pct = round(error_count * 100.0 / request_count, 2) | sort by TimeGenerated asc | project time = TimeGenerated, request_count, error_count, avg_duration_ms, p95_duration_ms, error_rate_pct', duration: 'PT1H' },
      { name: 'app_events', kql: 'AppEvents | take 1', duration: 'PT1H' },
    ];

    const results = [];
    for (const test of tests) {
      try {
        const r = await client.queryWorkspace(wsId, test.kql, { duration: test.duration });
        results.push({
          name: test.name,
          status: 'ok',
          rows: r.tables?.[0]?.rows?.length || 0,
          columns: r.tables?.[0]?.columnDescriptors?.map(c => c.name) || [],
        });
      } catch (err) {
        results.push({
          name: test.name,
          status: 'error',
          error: err.message,
          code: err.code,
          details: err.details || null,
        });
      }
    }

    res.json({ results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Journey Funnel ────────────────────────────────────────

router.get('/v1/admin/monitoring/journey-funnels', async (req, res) => {
  try {
    const journeyId = req.query.journeyId;
    const timeRange = validateTimeRange(req.query.timeRange);

    if (!journeyId || !VALID_JOURNEYS.includes(journeyId)) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: `journeyId must be one of: ${VALID_JOURNEYS.join(', ')}`,
      });
    }

    const steps = await queryJourneyFunnel(journeyId, timeRange);
    res.json({ journeyId, timeRange, steps });
  } catch (err) {
    console.error('[MONITORING] journey-funnels error:', err.message, err.details || '');
    res.status(500).json({ error: 'query_error', error_description: err.message, details: err.details || null });
  }
});

// ─── Step Performance ──────────────────────────────────────

router.get('/v1/admin/monitoring/journey-performance', async (req, res) => {
  try {
    const timeRange = validateTimeRange(req.query.timeRange);
    const steps = await queryStepPerformance(timeRange);
    res.json({ timeRange, steps });
  } catch (err) {
    console.error('[MONITORING] journey-performance error:', err.message, err.details || '');
    res.status(500).json({ error: 'query_error', error_description: err.message, details: err.details || null });
  }
});

// ─── Error Rate by Step ────────────────────────────────────

router.get('/v1/admin/monitoring/journey-errors', async (req, res) => {
  try {
    const timeRange = validateTimeRange(req.query.timeRange);
    const steps = await queryStepErrors(timeRange);
    res.json({ timeRange, steps });
  } catch (err) {
    console.error('[MONITORING] journey-errors error:', err.message, err.details || '');
    res.status(500).json({ error: 'query_error', error_description: err.message, details: err.details || null });
  }
});

// ─── Backend Health Overview ───────────────────────────────

router.get('/v1/admin/monitoring/overview', async (req, res) => {
  try {
    const timeRange = validateTimeRange(req.query.timeRange);
    const timeseries = await queryHealthOverview(timeRange);
    res.json({ timeRange, timeseries });
  } catch (err) {
    console.error('[MONITORING] overview error:', err.message, err.details || '');
    res.status(500).json({ error: 'query_error', error_description: err.message, details: err.details || null });
  }
});

export default router;
