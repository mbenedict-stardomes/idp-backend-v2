import { DefaultAzureCredential } from '@azure/identity';
import { LogsQueryClient } from '@azure/monitor-query-logs';

async function test() {
  try {
    const cred = new DefaultAzureCredential();
    const client = new LogsQueryClient(cred);
    const workspaceId = '21695459-a138-4950-963d-2ed08c81019d';
    
    console.log('Querying Log Analytics...');
    const result = await client.queryWorkspace(workspaceId, 'AppEvents | take 1', { duration: 'PT1H' });
    console.log('Success!', result.tables ? result.tables.length : 0, 'tables returned');
  } catch (err) {
    console.error('Error:', err.message);
  }
}

test();
