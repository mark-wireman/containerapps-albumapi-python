#Reference:
#https://learn.microsoft.com/en-us/azure/container-apps/tutorial-code-to-cloud?tabs=bash%2Cpython&pivots=acr-remote

az login
az upgrade
az extension add --name containerapp --upgrade

az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.OperationalInsights

$RESOURCE_GROUP="album-containerapps"
$LOCATION="eastus"
$ENVIRONMENT="env-album-containerapps"
$API_NAME="album-api"
$FRONTEND_NAME="album-ui"
$GITHUB_USERNAME="seccodingguy"
$ACR_NAME="acaalbums"+$GITHUB_USERNAME

az group delete --name $RESOURCE_GROUP --force
#Remove-Item "code-to-cloud-csharp"

#git clone https://github.com/%GITHUB_USERNAME%/containerapps-albumapi-csharp.git code-to-cloud-csharp

#cd code-to-cloud-csharp/src

az group create --name $RESOURCE_GROUP --location $LOCATION

az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic --admin-enabled true

az acr build --registry $ACR_NAME --image $API_NAME .

az containerapp env create --name $ENVIRONMENT --resource-group $RESOURCE_GROUP --location $LOCATION

az containerapp create --name $API_NAME --resource-group $RESOURCE_GROUP --environment $ENVIRONMENT --image $ACR_NAME.azurecr.io/$API_NAME --target-port 8080 --ingress external --registry-server $ACR_NAME.azurecr.io --query properties.configuration.ingress.fqdn

