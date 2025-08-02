#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Updates Network Security Group rules to allow Squid proxy traffic.

.DESCRIPTION
    This script adds NSG rules to allow inbound traffic on the Squid proxy port.
    It reads parameters from script arguments first, then from parameters.json file.

.PARAMETER ResourceGroupName
    Name of the Azure resource group (default: "squidder-rg")

.PARAMETER NSGName
    Name of the Network Security Group (default: "squidder-nsg")

.PARAMETER SquidPort
    Squid proxy port to allow (default: 3128)

.PARAMETER SourceAddressPrefix
    Source address prefix for the rule (default: "*" for any source)

.PARAMETER Priority
    Priority for the NSG rule (default: 310)

.EXAMPLE
    ./UpdateNSGRules.ps1
    ./UpdateNSGRules.ps1 -ResourceGroupName "my-proxy-rg" -NSGName "my-nsg"
    ./UpdateNSGRules.ps1 -SquidPort 8080 -SourceAddressPrefix "10.0.0.0/8"
#>

[CmdletBinding()]
param(
    [string]$ResourceGroupName = "squidder-us-rg",
    [string]$NSGName = "squidder-nsg",
    [int]$SquidPort = 3128,
    [string]$SourceAddressPrefix = "*",
    [int]$Priority = 310
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ParametersFile = Join-Path $ScriptDir "parameters.json"

Write-Host "=== Azure NSG Rules Update Script ===" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "NSG Name: $NSGName" -ForegroundColor Yellow
Write-Host "Squid Port: $SquidPort" -ForegroundColor Yellow
Write-Host "Source Address: $SourceAddressPrefix" -ForegroundColor Yellow
Write-Host "Priority: $Priority" -ForegroundColor Yellow

#region Module Management
Write-Host "`n--- Checking PowerShell Modules ---" -ForegroundColor Green

$RequiredModules = @(
    @{ Name = "Az.Accounts"; MinVersion = "2.0.0" }
    @{ Name = "Az.Network"; MinVersion = "4.0.0" }
)

foreach ($Module in $RequiredModules) {
    Write-Host "Checking module: $($Module.Name)" -ForegroundColor Yellow
    
    $InstalledModule = Get-Module -ListAvailable -Name $Module.Name | 
                     Where-Object { $_.Version -ge [Version]$Module.MinVersion } | 
                     Sort-Object Version -Descending | 
                     Select-Object -First 1
    
    if (-not $InstalledModule) {
        Write-Host "Installing module: $($Module.Name)" -ForegroundColor Cyan
        try {
            Install-Module -Name $Module.Name -MinimumVersion $Module.MinVersion -Force -AllowClobber -Scope CurrentUser
            Write-Host "Successfully installed $($Module.Name)" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install module $($Module.Name): $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "Module $($Module.Name) version $($InstalledModule.Version) is already installed" -ForegroundColor Green
    }
    
    # Import the module
    Import-Module $Module.Name -Force
}
#endregion

#region Azure Authentication
Write-Host "`n--- Azure Authentication ---" -ForegroundColor Green

# Check if already logged in
$Context = Get-AzContext -ErrorAction SilentlyContinue
if (-not $Context -or -not $Context.Account) {
    Write-Host "No active Azure session found. Initiating login..." -ForegroundColor Yellow
    try {
        Connect-AzAccount
        $Context = Get-AzContext
        Write-Host "Successfully logged in as: $($Context.Account.Id)" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to authenticate with Azure: $($_.Exception.Message)"
    }
}
else {
    Write-Host "Using existing Azure session: $($Context.Account.Id)" -ForegroundColor Green
    Write-Host "Subscription: $($Context.Subscription.Name) ($($Context.Subscription.Id))" -ForegroundColor Yellow
}
#endregion

#region Parameter Management
Write-Host "`n--- Parameter Management ---" -ForegroundColor Green

# Read existing parameters from parameters.json if available
$ExistingParams = @{}
if (Test-Path $ParametersFile) {
    try {
        $ParametersContent = Get-Content $ParametersFile | ConvertFrom-Json
        
        # Extract parameters that have values
        foreach ($param in $ParametersContent.parameters.PSObject.Properties) {
            if ($param.Value.value -ne $null -and $param.Value.value -ne "") {
                $ExistingParams[$param.Name] = $param.Value.value
            }
        }
        Write-Host "Loaded parameters from parameters.json" -ForegroundColor Green
        
        # Use parameters.json values if script parameters use defaults
        if ($ResourceGroupName -eq "squidder-us-rg" -and $ExistingParams.ContainsKey("resourceGroupName")) {
            $ResourceGroupName = $ExistingParams.resourceGroupName
            Write-Host "Using Resource Group from parameters.json: $ResourceGroupName" -ForegroundColor Yellow
        }
        
        if ($NSGName -eq "squidder-nsg" -and $ExistingParams.ContainsKey("networkSecurityGroups_squidder_nsg_name")) {
            $NSGName = $ExistingParams.networkSecurityGroups_squidder_nsg_name
            Write-Host "Using NSG name from parameters.json: $NSGName" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Could not read parameters.json: $($_.Exception.Message)"
    }
}

Write-Host "Final parameters:" -ForegroundColor Green
Write-Host "  Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host "  NSG Name: $NSGName" -ForegroundColor White
Write-Host "  Squid Port: $SquidPort" -ForegroundColor White
Write-Host "  Source Address: $SourceAddressPrefix" -ForegroundColor White
#endregion

#region NSG Validation and Update
Write-Host "`n--- NSG Validation and Update ---" -ForegroundColor Green

# Check if NSG exists
Write-Host "Checking if NSG '$NSGName' exists..." -ForegroundColor Yellow
$NSG = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $NSGName -ErrorAction SilentlyContinue

if (-not $NSG) {
    Write-Error "Network Security Group '$NSGName' not found in resource group '$ResourceGroupName'"
}

Write-Host "NSG found: $($NSG.Name)" -ForegroundColor Green
Write-Host "Location: $($NSG.Location)" -ForegroundColor White
Write-Host "Current security rules count: $($NSG.SecurityRules.Count)" -ForegroundColor White

# Display current rules
Write-Host "`nCurrent Security Rules:" -ForegroundColor Cyan
foreach ($rule in $NSG.SecurityRules) {
    $directionColor = if ($rule.Direction -eq "Inbound") { "Yellow" } else { "Magenta" }
    $accessColor = if ($rule.Access -eq "Allow") { "Green" } else { "Red" }
    
    Write-Host "  $($rule.Name) - " -NoNewline -ForegroundColor White
    Write-Host "$($rule.Direction) " -NoNewline -ForegroundColor $directionColor
    Write-Host "$($rule.Access) " -NoNewline -ForegroundColor $accessColor
    Write-Host "Port: $($rule.DestinationPortRange) " -NoNewline -ForegroundColor White
    Write-Host "Priority: $($rule.Priority)" -ForegroundColor Gray
}

# Check if Squid proxy rule already exists
$ExistingSquidRule = $NSG.SecurityRules | Where-Object { 
    $_.DestinationPortRange -eq $SquidPort.ToString() -or 
    $_.Name -like "*Squid*" -or 
    $_.Name -like "*Proxy*" 
}

if ($ExistingSquidRule) {
    Write-Host "`nExisting Squid/Proxy rule found:" -ForegroundColor Yellow
    foreach ($rule in $ExistingSquidRule) {
        Write-Host "  Name: $($rule.Name)" -ForegroundColor White
        Write-Host "  Port: $($rule.DestinationPortRange)" -ForegroundColor White
        Write-Host "  Priority: $($rule.Priority)" -ForegroundColor White
        Write-Host "  Access: $($rule.Access)" -ForegroundColor White
    }
    
    $UpdateChoice = Read-Host "`nDo you want to update/replace the existing rule? (Y/N)"
    if ($UpdateChoice -notmatch '^[Yy]') {
        Write-Host "Skipping NSG rule update" -ForegroundColor Yellow
        exit 0
    }
    
    # Remove existing rules
    foreach ($rule in $ExistingSquidRule) {
        Write-Host "Removing existing rule: $($rule.Name)" -ForegroundColor Yellow
        $NSG = Remove-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $NSG -Name $rule.Name
    }
}

# Add new Squid proxy rule
Write-Host "`nAdding Squid proxy rule..." -ForegroundColor Yellow
$RuleName = "SquidProxy"

try {
    $NSG = Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $NSG `
        -Name $RuleName `
        -Protocol "TCP" `
        -Direction "Inbound" `
        -Priority $Priority `
        -SourceAddressPrefix $SourceAddressPrefix `
        -SourcePortRange "*" `
        -DestinationAddressPrefix "*" `
        -DestinationPortRange $SquidPort.ToString() `
        -Access "Allow" `
        -Description "Allow inbound traffic to Squid proxy server on port $SquidPort"
    
    Write-Host "Squid proxy rule added to NSG configuration" -ForegroundColor Green
}
catch {
    Write-Error "Failed to add NSG rule: $($_.Exception.Message)"
}

# Apply the changes to Azure
Write-Host "Applying NSG changes to Azure..." -ForegroundColor Yellow
try {
    $UpdateResult = Set-AzNetworkSecurityGroup -NetworkSecurityGroup $NSG
    
    if ($UpdateResult.ProvisioningState -eq "Succeeded") {
        Write-Host "NSG rules updated successfully!" -ForegroundColor Green
    }
    else {
        Write-Warning "NSG update may have failed. Status: $($UpdateResult.ProvisioningState)"
    }
}
catch {
    Write-Error "Failed to update NSG: $($_.Exception.Message)"
}

# Verify the update
Write-Host "`nVerifying NSG update..." -ForegroundColor Yellow
$UpdatedNSG = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $NSGName

$NewSquidRule = $UpdatedNSG.SecurityRules | Where-Object { $_.Name -eq $RuleName }
if ($NewSquidRule) {
    Write-Host "✓ Squid proxy rule verified:" -ForegroundColor Green
    Write-Host "  Name: $($NewSquidRule.Name)" -ForegroundColor White
    Write-Host "  Port: $($NewSquidRule.DestinationPortRange)" -ForegroundColor White
    Write-Host "  Priority: $($NewSquidRule.Priority)" -ForegroundColor White
    Write-Host "  Source: $($NewSquidRule.SourceAddressPrefix)" -ForegroundColor White
    Write-Host "  Access: $($NewSquidRule.Access)" -ForegroundColor White
}
else {
    Write-Warning "Could not verify the new Squid proxy rule"
}
#endregion

#region Network Connectivity Test
Write-Host "`n--- Network Connectivity Test ---" -ForegroundColor Green

# Try to find associated VMs to test connectivity
$VMNetworkInterfaces = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName | Where-Object {
    $_.NetworkSecurityGroup.Id -like "*$NSGName*"
}

if ($VMNetworkInterfaces) {
    Write-Host "Found network interfaces associated with this NSG:" -ForegroundColor Yellow
    
    foreach ($nic in $VMNetworkInterfaces) {
        $VM = Get-AzVM -ResourceGroupName $ResourceGroupName | Where-Object { 
            $_.NetworkProfile.NetworkInterfaces.Id -contains $nic.Id 
        }
        
        if ($VM) {
            Write-Host "  VM: $($VM.Name)" -ForegroundColor White
            
            # Get public IP if available
            $PublicIP = $nic.IpConfigurations | ForEach-Object {
                if ($_.PublicIpAddress) {
                    Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName | Where-Object {
                        $_.Id -eq $_.PublicIpAddress.Id
                    }
                }
            } | Select-Object -First 1
            
            if ($PublicIP -and $PublicIP.IpAddress) {
                Write-Host "  Public IP: $($PublicIP.IpAddress)" -ForegroundColor White
                Write-Host "  Proxy URL: http://$($PublicIP.IpAddress):$SquidPort" -ForegroundColor Cyan
                
                # Test port connectivity
                Write-Host "  Testing port $SquidPort connectivity..." -ForegroundColor Yellow
                try {
                    $TestResult = Test-NetConnection -ComputerName $PublicIP.IpAddress -Port $SquidPort -WarningAction SilentlyContinue
                    if ($TestResult.TcpTestSucceeded) {
                        Write-Host "  ✓ Port $SquidPort is accessible" -ForegroundColor Green
                    }
                    else {
                        Write-Host "  ✗ Port $SquidPort is not accessible (may need time to propagate)" -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Host "  ⚠ Could not test connectivity: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
    }
}
else {
    Write-Host "No network interfaces found associated with this NSG" -ForegroundColor Yellow
}
#endregion

#region Summary
Write-Host "`n=== NSG Update Summary ===" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host "NSG Name: $NSGName" -ForegroundColor White
Write-Host "Rule Added: $RuleName" -ForegroundColor White
Write-Host "Port Allowed: $SquidPort (TCP Inbound)" -ForegroundColor White
Write-Host "Source Address: $SourceAddressPrefix" -ForegroundColor White
Write-Host "Priority: $Priority" -ForegroundColor White

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "1. Run ConfigureSquidProxy.ps1 to install Squid on the VM" -ForegroundColor White
Write-Host "2. Test proxy connectivity using the proxy URLs shown above" -ForegroundColor White
Write-Host "3. Configure your applications to use the proxy server" -ForegroundColor White

Write-Host "`nNSG Rule Management Commands:" -ForegroundColor Yellow
Write-Host "  View all rules: Get-AzNetworkSecurityGroup -ResourceGroupName '$ResourceGroupName' -Name '$NSGName' | Select-Object -ExpandProperty SecurityRules" -ForegroundColor White
Write-Host "  Remove this rule: Remove-AzNetworkSecurityRuleConfig -NetworkSecurityGroup `$nsg -Name '$RuleName'" -ForegroundColor White
#endregion

Write-Host "`n=== NSG Update Script Completed ===" -ForegroundColor Cyan