import 'dotenv/config';

const env = {
  PORT: parseInt(process.env.PORT, 10) || 8080,

  // Database (Azure AD via Managed Identity in Azure, DefaultAzureCredential locally)
  DB_SERVER: process.env.DB_SERVER || 'empaysql-t.database.windows.net',
  DB_NAME: process.env.DB_NAME || 'sqldb-authenticator-poc',
  AZURE_CLIENT_ID: process.env.AZURE_CLIENT_ID || '',

  // Service Bus and Storage Connection Strings
  SB_CONNECTION_STRING: process.env.SB_CONNECTION_STRING,
  SB_TOPIC_IDP: process.env.SB_TOPIC_IDP || 'idp-events-poc',
  STORAGE_CONNECTION_STRING: process.env.STORAGE_CONNECTION_STRING || '',

  // OIDC
  ISSUER_URL:
    process.env.ISSUER_URL || 'https://idp-kong-gateway-poc-app.jollyforest-2769ae0c.uaenorth.azurecontainerapps.io',

  // App Insights
  APP_INSIGHTS_CONNECTION_STRING: process.env.APP_INSIGHTS_CONNECTION_STRING || '',

  // Log Analytics (for monitoring query API)
  LOG_ANALYTICS_WORKSPACE_ID: process.env.LOG_ANALYTICS_WORKSPACE_ID || '',

  // Service Account Authentication
  AUTH_TOKEN_SECRET: process.env.AUTH_TOKEN_SECRET || 'your-super-secret-key-change-in-production',
  AUTH_TOKEN_EXPIRY_SECONDS: parseInt(process.env.AUTH_TOKEN_EXPIRY_SECONDS || '3600', 10),
};

export default env;
