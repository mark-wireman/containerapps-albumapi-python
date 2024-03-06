#### START ELEVATE TO ADMIN #####
param(
    [Parameter(Mandatory=$false)]
    [switch]$shouldAssumeToBeElevated,

    [Parameter(Mandatory=$false)]
    [String]$workingDirOverride
)

# If parameter is not set, we are propably in non-admin execution. We set it to the current working directory so that
#  the working directory of the elevated execution of this script is the current working directory
if(-not($PSBoundParameters.ContainsKey('workingDirOverride')))
{
    $workingDirOverride = (Get-Location).Path
}

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# If we are in a non-admin execution. Execute this script as admin
if ((Test-Admin) -eq $false)  {
    if ($shouldAssumeToBeElevated) {
        Write-Output "Elevating did not work :("

    } else {
        #                                                         vvvvv add `-noexit` here for better debugging vvvvv 
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -file "{0}" -shouldAssumeToBeElevated -workingDirOverride "{1}"' -f ($myinvocation.MyCommand.Definition, "$workingDirOverride"))
    }
    exit
}

Set-Location "$workingDirOverride"
##### END ELEVATE TO ADMIN #####

# Add actual commands to be executed in elevated mode here:
Write-Output "Running script as an admin."

Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force
#Install-Module -Name Az.App CurrentUser -Repository PSGallery -Force
Register-AzResourceProvider -ProviderNamespace Microsoft.App -AsJob
Register-AzResourceProvider -ProviderNamespace Microsoft.OperationalInsights -AsJob

$ResourceGroup = "album-containerapps"
$Location = "eastus"
$Environment = "env-album-containerapps"
$APIName="album-api"
$FrontendName="album-ui"
$GITHUB_USERNAME = "seccodingguy"
$ACRName="acaalbums"+$GITHUB_USERNAME

Connect-AzAccount
Remove-AzResourceGroup -Name $ResourceGroup -Force

#az group create --name $RESOURCE_GROUP --location "$LOCATION"
New-AzResourceGroup -Location $Location -Name $ResourceGroup

#az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic --admin-enabled true
$acr = New-AzContainerRegistry -ResourceGroupName $ResourceGroup -Location $Location -Name $ACRName -Sku Basic -EnableAdminUser

#az acr build --registry $ACR_NAME --image $API_NAME .
az acr build --registry $ACRName --image $APIName .

#az containerapp env create --name $ENVIRONMENT --resource-group $RESOURCE_GROUP --location "$LOCATION"
$WorkspaceArgs = @{
    Name = 'my-album-workspace'
    ResourceGroupName = $ResourceGroup
    Location = $Location
    PublicNetworkAccessForIngestion = 'Enabled'
    PublicNetworkAccessForQuery = 'Enabled'
}
New-AzOperationalInsightsWorkspace @WorkspaceArgs
$WorkspaceId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -Name $WorkspaceArgs.Name).CustomerId
$WorkspaceSharedKey = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $ResourceGroup -Name $WorkspaceArgs.Name).PrimarySharedKey

#az containerapp create --name $API_NAME --resource-group $RESOURCE_GROUP --environment $ENVIRONMENT --image $ACR_NAME+".azurecr.io/"+$API_NAME --target-port 8080 --ingress external --registry-server $ACR_NAME+".azurecr.io" --query "properties.configuration.ingress.fqdn"
$EnvArgs = @{
    EnvName = $Environment
    ResourceGroupName = $ResourceGroup
    Location = $Location
    AppLogConfigurationDestination = 'log-analytics'
    LogAnalyticConfigurationCustomerId = $WorkspaceId
    LogAnalyticConfigurationSharedKey = $WorkspaceSharedKey
}

New-AzContainerAppManagedEnv @EnvArgs

$ImageParams = @{
    Name = $APIName
    Image = $ACRName + '.azurecr.io/' + $APIName + ':latest'
}
$TemplateObj = New-AzContainerAppTemplateObject @ImageParams

$RegistryCredentials = Get-AzContainerRegistryCredential -Name $ACRName -ResourceGroupName $ResourceGroup

$RegistryArgs = @{
    Server = $ACRName + '.azurecr.io'
    PasswordSecretRef = 'registrysecret'
    Username = $RegistryCredentials.Username
}
$RegistryObj = New-AzContainerAppRegistryCredentialObject @RegistryArgs

$SecretObj = New-AzContainerAppSecretObject -Name 'registrysecret' -Value $RegistryCredentials.Password

$EnvId = (Get-AzContainerAppManagedEnv -EnvName $Environment -ResourceGroup $ResourceGroup).Id

#$AppArgs = @{
#    Name = $APIName
#    Location = $Location
#    ResourceGroupName = $ResourceGroup
#    ManagedEnvironmentId = $EnvId
#    TemplateContainer = $TemplateObj
#    ConfigurationRegistry = $RegistryObj
#    ConfigurationSecret = $SecretObj
#    IngressTargetPort = 8080
#    IngressExternal = $True
#}

$configuration = New-AzContainerAppConfigurationObject -Name $APIName -Location $Location -ResourceGroup $ResourceGroup -IngressExternal:$True -IngressTargetPort 8080  -ManagedEnvironmentId $EnvId -TemplateContainer $TemplateObj -ConfigurationRegistry $RegistryObj -ConfigurationSecret $SecretObj
$MyApp = New-AzContainerApp $configuration

# show the app's fully qualified domain name (FQDN).
$MyApp.IngressFqdn

