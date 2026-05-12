import { DefaultAzureCredential } from '@azure/identity';
import { LogsQueryClient, LogsQueryResultStatus } from '@azure/monitor-query-logs';
import env from '../config/env.js';

let client = null;

function getClient() {
  if (!client) {
    const credential = new DefaultAzureCredential(
      env.AZURE_CLIENT_ID
        ? { managedIdentityClientId: env.AZURE_CLIENT_ID }
        : undefined
    );
    client = new LogsQueryClient(credential);
  }
  return client;
}

/**
 * Execute a KQL query against the Log Analytics workspace.
 * Returns an array of row objects (column name → value).
 */
async function executeQuery(kql, timeRange) {
  const workspaceId = env.LOG_ANALYTICS_WORKSPACE_ID;
  if (!workspaceId) {
    throw new Error('LOG_ANALYTICS_WORKSPACE_ID not configured');
  }

  const duration = parseDuration(timeRange);

  console.log(`[MONITORING] Querying workspace=${workspaceId} duration=${duration} kql_length=${kql.length}`);
  console.log(`[MONITORING] KQL preview: ${kql.trim().substring(0, 200)}`);

  const trimmedKql = kql.trim();

  let result;
  try {
    result = await getClient().queryWorkspace(workspaceId, trimmedKql, { duration });
  } catch (err) {
    console.error(`[MONITORING] SDK error: name=${err.name} code=${err.code} status=${err.statusCode} message=${err.message}`);
    if (err.details) console.error('[MONITORING] Error details:', JSON.stringify(err.details, null, 2));
    throw err;
  }

  if (result.status === LogsQueryResultStatus.Success) {
    console.log(`[MONITORING] Success: ${result.tables?.[0]?.rows?.length || 0} rows`);
    return tablesToRows(result.tables);
  }
  if (result.partialTables && result.partialTables.length > 0) {
    console.warn('[MONITORING] Partial result:', result.partialError?.message);
    return tablesToRows(result.partialTables);
  }
  throw new Error(`Query failed: ${result.partialError?.message || 'unknown error'}`);
}

function tablesToRows(tables) {
  if (!tables || tables.length === 0) return [];
  const table = tables[0];
  const columns = table.columnDescriptors.map(c => c.name);
  return table.rows.map(row => {
    const obj = {};
    columns.forEach((col, i) => { obj[col] = row[i]; });
    return obj;
  });
}

function parseDuration(timeRange) {
  const map = {
    '1h':  'PT1H',
    '4h':  'PT4H',
    '6h':  'PT6H',
    '12h': 'PT12H',
    '24h': 'P1D',
    '7d':  'P7D',
    '30d': 'P30D',
  };
  return map[timeRange] || 'P1D';
}

// ─── Journey Funnel ────────────────────────────────────────

const STEP_ORDERS = {
  FLOW_ONBOARD_REGISTRATION: {
    WELCOME: 0, REGISTER_IDENTITY: 1, VERIFY_PHONE: 2,
    BIOMETRIC_SETUP: 3, PIN_SETUP: 4, DEVICE_BINDING: 5, COMPLETE: 6,
  },
  FLOW_AUTH_CHALLENGE_APPROVAL: {
    CHALLENGE_LIST: 0, CHALLENGE_DETAIL: 1, BIOMETRIC_AUTH: 2,
    CHALLENGE_SUBMIT: 3, RESULT: 4,
  },
  FLOW_ACCOUNT_MANAGEMENT: {
    PROFILE_VIEW: 0, DEVICE_STATUS: 1, SECURITY_SETTINGS: 2, DEVICE_UNBIND: 3,
  },
};

export async function queryJourneyFunnel(journeyId, timeRange) {
  const steps = STEP_ORDERS[journeyId];
  if (!steps) throw new Error(`Unknown journey: ${journeyId}`);

  const firstStep = Object.keys(steps)[0];

  const kql = `
    let stepOrder = dynamic(${JSON.stringify(steps)});
    AppEvents
    | where Name == "JourneyStep"
    | where tostring(Properties.journey_id) == "${journeyId}"
    | extend
        step = tostring(Properties.journey_step),
        instance_id = tostring(Properties.journey_instance_id)
    | summarize instances = dcount(instance_id) by step
    | extend step_order = toint(stepOrder[step])
    | sort by step_order asc
    | extend first_step_count = toscalar(
        AppEvents
        | where Name == "JourneyStep"
        | where tostring(Properties.journey_id) == "${journeyId}"
        | where tostring(Properties.journey_step) == "${firstStep}"
        | summarize dcount(tostring(Properties.journey_instance_id))
    )
    | extend conversion_pct = round(instances * 100.0 / max_of(first_step_count, 1), 1)
    | project step, step_order, instances, conversion_pct
  `;

  return executeQuery(kql, timeRange);
}

// ─── Step Performance ──────────────────────────────────────

export async function queryStepPerformance(timeRange) {
  const kql = `
    AppEvents
    | where Name == "JourneyStep"
    | where tostring(Properties.source) == "backend"
    | extend
        step = tostring(Properties.journey_step),
        journey = tostring(Properties.journey_id),
        duration_ms = todouble(Properties.duration_ms)
    | where isnotnull(duration_ms)
    | summarize
        p50_ms = round(percentile(duration_ms, 50), 0),
        p95_ms = round(percentile(duration_ms, 95), 0),
        avg_ms = round(avg(duration_ms), 0),
        count = count()
        by journey, step
    | sort by journey asc, step asc
  `;

  return executeQuery(kql, timeRange);
}

// ─── Error Rate by Step ────────────────────────────────────

export async function queryStepErrors(timeRange) {
  const kql = `
    AppEvents
    | where Name == "JourneyStep"
    | extend
        step = tostring(Properties.journey_step),
        journey = tostring(Properties.journey_id),
        success = tostring(Properties.success)
    | summarize
        total = count(),
        failures = countif(success == "false")
        by journey, step
    | extend error_rate_pct = round(failures * 100.0 / total, 2)
    | sort by error_rate_pct desc
    | project journey, step, total, failures, error_rate_pct
  `;

  return executeQuery(kql, timeRange);
}

// ─── Backend Health Overview ───────────────────────────────

export async function queryHealthOverview(timeRange) {
  const kql = `
    AppRequests
    | summarize
        request_count = count(),
        error_count = countif(toint(ResultCode) >= 400),
        avg_duration_ms = round(avg(DurationMs), 0),
        p95_duration_ms = round(percentile(DurationMs, 95), 0)
        by bin(TimeGenerated, 5m)
    | extend error_rate_pct = round(error_count * 100.0 / request_count, 2)
    | sort by TimeGenerated asc
    | project timestamp = TimeGenerated, request_count, error_count, avg_duration_ms, p95_duration_ms, error_rate_pct
  `;

  return executeQuery(kql, timeRange);
}
