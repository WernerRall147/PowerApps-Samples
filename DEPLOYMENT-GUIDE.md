# PowerPlatform VNet Injection Deployment Guide

## 🎯 Overview

This repository contains a complete PowerPlatform VNet Injection solution that automates the entire deployment process, including test resources and validation tools.

## 📁 Current Structure

```
PowerApps-Samples/
├── Deploy-PowerPlatform-VNetInjection-Final.ps1  # ⭐ Main deployment script
├── Remove-PowerPlatform-VNetInjection.ps1        # Cleanup script
├── README.md                                       # Repository documentation
├── DEPLOYMENT-GUIDE.md                           # This guide
└── templates/                                     # ARM templates and test resources
    ├── testing-resources.json                    # ARM template for test infrastructure
    └── test-app/
        └── index.html                            # Test web application
```

## 🚀 Main Features

### Deploy-PowerPlatform-VNetInjection-Final.ps1

**Complete end-to-end VNet injection deployment with the following capabilities:**

#### Phase 1: Prerequisites & Connection
- ✅ Validates PowerShell 5.1+ and Azure PowerShell module
- ✅ Establishes Azure connection and subscription context
- ✅ Configuration file support for repeatable deployments

#### Phase 2: VNet Setup & Subnet Delegation
- ✅ Automatically configures subnet delegation for `Microsoft.PowerPlatform/enterprisePolicies`
- ✅ Validates existing VNet and subnet configuration
- ✅ Handles existing delegations gracefully

#### Phase 3: Enterprise Policy Creation
- ✅ Creates PowerPlatform enterprise policy
- ✅ Links policy to specified VNet and subnet
- ✅ Configures proper permissions and ARM resource IDs

#### Phase 4: Test Infrastructure Deployment
- ✅ **NEW**: Deploys Azure App Service with VNet integration
- ✅ **NEW**: Deploys Storage Account for connectivity testing
- ✅ **NEW**: Multi-region deployment support (Primary + Secondary)
- ✅ **NEW**: Automated test application deployment

#### Phase 5: Environment Linking
- ✅ Links enterprise policy to PowerPlatform environment
- ✅ Activates VNet injection for specified environment

## 🛠 Usage Examples

### Basic Deployment (Interactive)
```powershell
.\Deploy-PowerPlatform-VNetInjection-Final.ps1
```

### Advanced Deployment with Parameters
```powershell
.\Deploy-PowerPlatform-VNetInjection-Final.ps1 `
    -VirtualNetworkSubscriptionId "your-subscription-id" `
    -VirtualNetworkName "myVnet" `
    -SubnetName "mySubnet" `
    -ResourceGroup "myResourceGroup" `
    -EnterprisePolicyName "myEnterprisePolicy" `
    -EnterprisePolicyLocation "East US" `
    -EnvironmentId "your-environment-id" `
    -DeployTestResources:$true `
    -ResourcePrefix "ppvnet"
```

### Configuration File Deployment
```powershell
# Create config file (example)
@{
    SubscriptionId = "<#TODO>"
    ResourceGroupName = "myResourceGroup" 
    VirtualNetworkName = "myVnet"
    SubnetName = "mySubnet"
    EnterprisePolicyName = "myEnterprisePolicy"
    PrimaryRegion = "East US"
    SecondaryRegion = "West US"
    EnvironmentId = "your-env-id"
    ResourcePrefix = "ppvnet"
} | ConvertTo-Json | Set-Content "config.json"

# Deploy using config
.\Deploy-PowerPlatform-VNetInjection-Final.ps1 -ConfigFile "config.json"
```

## 🧪 Test Infrastructure

### ARM Template (`templates/testing-resources.json`)
**Deploys comprehensive testing infrastructure:**

- **App Service Plan**: Basic tier for cost efficiency
- **Web App**: With VNet integration enabled
- **Storage Account**: For connectivity testing
- **Outputs**: All resource details for validation

### Test Application (`templates/test-app/index.html`)
**Interactive web application for validation:**

- **Connectivity Tests**: Storage, outbound, network info
- **VNet Status**: Shows integration status
- **Real-time Results**: Live testing interface
- **Visual Interface**: Professional styling with status indicators

## 🔧 Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `VirtualNetworkSubscriptionId` | Azure subscription containing VNet | `"<#TODO>"` |
| `VirtualNetworkName` | Target virtual network name | `"myVnet"` |
| `SubnetName` | Target subnet for delegation | `"mySubnet"` |
| `ResourceGroup` | Resource group for enterprise policy | `"myResourceGroup"` |
| `EnterprisePolicyName` | Name for PowerPlatform policy | `"myEnterprisePolicy"` |
| `EnterprisePolicyLocation` | Primary Azure region | `"East US"` |
| `SecondaryRegion` | Secondary region for testing | `"West US"` |
| `EnvironmentId` | PowerPlatform environment ID | `""` (prompt if empty) |
| `DeployTestResources` | Deploy test infrastructure | `$true` |
| `ResourcePrefix` | Prefix for test resources | `"ppvnet"` |

## 📊 Deployment Output

After successful deployment, you'll receive:

### 1. Configuration Summary
- Subscription and resource details
- VNet and subnet information
- Enterprise policy details

### 2. Test Resources (if enabled)
- **Primary Region**: App Service + Storage Account
- **Secondary Region**: App Service + Storage Account  
- **Test URLs**: Direct links to test applications

### 3. Next Steps
- Verification instructions
- Manual linking commands (if environment ID not provided)
- Test connectivity guidance

## 🧹 Cleanup

Use the cleanup script to remove all deployed resources:

```powershell
.\Remove-PowerPlatform-VNetInjection.ps1 `
    -ResourceGroup "myResourceGroup" `
    -EnterprisePolicyName "myEnterprisePolicy"
```

## ✅ Validation

### Automatic Validation
The script includes built-in validation for:
- PowerShell and module prerequisites
- Azure connectivity and permissions
- VNet and subnet existence
- ARM template deployment status

### Manual Validation Steps
1. **Azure Portal**: Verify subnet delegation
2. **Test Applications**: Use deployed web apps for connectivity testing
3. **PowerPlatform Admin Center**: Confirm environment VNet injection status
4. **PowerApps Flow**: Test actual flow connectivity

## 🚨 Prerequisites

1. **PowerShell 5.1+**
2. **Azure PowerShell Module**: `Install-Module -Name Az`
3. **Azure Permissions**: Contributor access to subscription and resource groups
4. **Existing VNet**: Virtual network with available subnet for delegation

## 📝 Notes

- **VNet injection** is configured entirely via PowerShell (no UI option)
- **Test resources** are optional but recommended for validation
- **Multi-region** deployment helps test failover scenarios
- **Enterprise policies** require specific PowerPlatform API calls (simulated in script)

## 🔗 Related Documentation

- [Power Platform VNet Integration](https://docs.microsoft.com/en-us/power-platform/admin/managed-environment-overview)
- [Azure VNet Subnet Delegation](https://docs.microsoft.com/en-us/azure/virtual-network/subnet-delegation-overview)
- [PowerApps Flow Connectivity](https://docs.microsoft.com/en-us/power-automate/overview-cloud)
