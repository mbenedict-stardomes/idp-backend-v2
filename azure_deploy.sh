# 1. Set env var on Container App (so it doesn't depend on .env file)
az containerapp update \
  --name idp-capp-service-poc-core \
  --resource-group rg-iot-test \
  --set-env-vars \
    "APP_INSIGHTS_CONNECTION_STRING=InstrumentationKey=5fcd5b59-1305-494f-a5e4-dc0e4a0f5cb9;IngestionEndpoint=https://uaenorth-0.in.applicationinsights.azure.com/;LiveEndpoint=https://uaenorth.livediagnostics.monitor.azure.com/;ApplicationId=022388e6-a082-497d-8d8d-94849c799e07"

# 2. Rebuild and push
az acr build --registry acriottest --image idp-core:latest /Users/manohar/Documents/08_IdP_Development/01_IdP_Solution_v2/01_Backend_v2/

# 3. Force new revision
az containerapp update \
  --name idp-capp-service-poc-core \
  --resource-group rg-iot-test \
  --image acriottest.azurecr.io/idp-core:latest

# 4. Check logs — should see [TELEMETRY] message now
az containerapp logs show \
  --name idp-capp-service-poc-core \
  --resource-group rg-iot-test \
  --tail 30

