$virtualNetworkSubscriptionId = "0"
$virtualNetworkName = "0"
$subnetName = "0"
$resourceGroup = "0"
$enterprisePolicyName = "0"
$enterprisePolicyLocation = "0"
$vnetId = 0
$environmentId = 0
$policyArmId  = 0
$endpoint = 0

#from SetupVnetForSubnetDelegation.ps1
AzureLogin
$setSubscription = Set-AzContext -Subscription $virtualNetworkSubscriptionId
$virtualNetwork = Get-AzVirtualNetwork -Name $virtualNetworkName
$subnet = Get-AzVirtualNetworkSubnetConfig -Name $subnetName -VirtualNetwork $virtualNetwork
$subnet = Add-AzDelegation -Name "Microsoft.PowerPlatform/enterprisePolicies" -ServiceName "Microsoft.PowerPlatform/enterprisePolicies" -Subnet $subnet
Set-AzVirtualNetwork -VirtualNetwork $virtualNetwork

#from CreateSubnetInjectionEnterprisePolicy.ps1
$body = GenerateEnterprisePolicyBody -policyType "vnet" -policyLocation $enterprisePolicyLocation -policyName $enterprisePolicyName -vnetId $vnetId -subnetName $subnetName
$result = PutEnterprisePolicy $resourceGroup $body
$policyArmId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.PowerPlatform/enterprisePolicies/$enterprisePolicyName"
$policy = GetEnterprisePolicy $policyArmId
$policyString = $policy | ConvertTo-Json -Depth 7
Write-Host "Policy created"

#Permissions
$userguid = (Get-AzContext).Account.Id
New-AzRoleAssignment -ObjectId $userguid -RoleDefinitionName Reader -Scope $policyArmId

#from NewSubnetInjection.ps1
$environmentId = Get-PowerPlatformEnvironmentId
LinkPolicyToEnv -policyType vnet -environmentId $environmentId -policyArmId $policyArmId -endpoint $endpoint 
