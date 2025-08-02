#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Creates and configures a Squid proxy server in Azure using ARM templates.

.DESCRIPTION
    This script deploys an Azure VM with Squid proxy server using ARM templates.
    It's designed to be idempotent and includes testing of the proxy functionality.

.PARAMETER ResourceGroupName
    Name of the Azure resource group (default: "squidder-rg")

.PARAMETER Location
    Azure region for deployment (default: "australiaeast")

.PARAMETER VMName
    Name of the virtual machine (default: "squidder")

.EXAMPLE
    ./AzureCreateProxy.ps1
    ./AzureCreateProxy.ps1 -ResourceGroupName "my-proxy-rg" -Location "eastus"
#>

[CmdletBinding()]
param(
    [string]$ResourceGroupName = "squidder-us-rg",
    [string]$Location = "eastus",
    [string]$VMName = "squidderus",
    [string]$AdminUsername = "azureuser",
    [int]$SquidPort = 3128,
    [string]$AllowedNetworks = "0.0.0.0/0"
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$TemplateFile = Join-Path $ScriptDir "template.json"
$ParametersFile = Join-Path $ScriptDir "parameters.json"

#region Password Management
Write-Host "=== Azure Squid Proxy Deployment Script ===" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "Location: $Location" -ForegroundColor Yellow
Write-Host "VM Name: $VMName" -ForegroundColor Yellow
Write-Host "Squid Port: $SquidPort" -ForegroundColor Yellow
Write-Host "Allowed Networks: $AllowedNetworks" -ForegroundColor Yellow

# Get admin password from environment variable or prompt
$AdminPassword = $null
$EnvPassword = $env:AZURE_ADMIN_PASSWORD

if ($EnvPassword) {
    Write-Host "Using admin password from environment variable AZURE_ADMIN_PASSWORD" -ForegroundColor Green
    $AdminPassword = ConvertTo-SecureString -String $EnvPassword -AsPlainText -Force
}
else {
    Write-Host "Environment variable AZURE_ADMIN_PASSWORD not set" -ForegroundColor Yellow
    $AdminPassword = Read-Host "Enter admin password for VM" -AsSecureString
    if (-not $AdminPassword -or $AdminPassword.Length -eq 0) {
        Write-Error "Admin password is required"
    }
}
#endregion

#region Module Management
Write-Host "`n--- Checking PowerShell Modules ---" -ForegroundColor Green

$RequiredModules = @(
    @{ Name = "Az.Accounts"; MinVersion = "2.0.0" }
    @{ Name = "Az.Resources"; MinVersion = "4.0.0" }
    @{ Name = "Az.Compute"; MinVersion = "4.0.0" }
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

#region Azure Feature Validation
Write-Host "`n--- Azure Feature Validation ---" -ForegroundColor Green

# Check required Azure features and resource providers
$RequiredProviders = @(
    "Microsoft.Compute",
    "Microsoft.Network"
)

foreach ($Provider in $RequiredProviders) {
    Write-Host "Checking resource provider: $Provider" -ForegroundColor Yellow
    $ProviderStatus = Get-AzResourceProvider -ProviderNamespace $Provider
    
    if ($ProviderStatus.RegistrationState -ne "Registered") {
        Write-Host "Registering resource provider: $Provider" -ForegroundColor Cyan
        try {
            Register-AzResourceProvider -ProviderNamespace $Provider
            Write-Host "Resource provider $Provider registered successfully" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to register resource provider $Provider : $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "Resource provider $Provider is already registered" -ForegroundColor Green
    }
}

# Check subscription limits
Write-Host "Checking subscription quotas..." -ForegroundColor Yellow
try {
    $ComputeUsage = Get-AzVMUsage -Location $Location | Where-Object { $_.Name.LocalizedValue -eq "Standard BS Family vCPUs" }
    if ($ComputeUsage) {
        $Available = $ComputeUsage.Limit - $ComputeUsage.CurrentValue
        Write-Host "Available Standard BS Family vCPUs: $Available" -ForegroundColor $(if ($Available -gt 0) { "Green" } else { "Red" })
        if ($Available -le 0) {
            Write-Warning "No available vCPUs for Standard BS Family. Consider using a different VM size or location."
        }
    }
}
catch {
    Write-Warning "Could not check compute quotas: $($_.Exception.Message)"
}
#endregion

#region Resource Group Management
Write-Host "`n--- Resource Group Management ---" -ForegroundColor Green

$ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $ResourceGroup) {
    Write-Host "Creating resource group: $ResourceGroupName" -ForegroundColor Yellow
    try {
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
        Write-Host "Resource group created successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create resource group: $($_.Exception.Message)"
    }
}
else {
    Write-Host "Resource group '$ResourceGroupName' already exists" -ForegroundColor Green
}
#endregion

#region Template Validation and Deployment
Write-Host "`n--- ARM Template Deployment ---" -ForegroundColor Green

# Verify template files exist
if (-not (Test-Path $TemplateFile)) {
    Write-Error "Template file not found: $TemplateFile"
}
if (-not (Test-Path $ParametersFile)) {
    Write-Error "Parameters file not found: $ParametersFile"
}

# Password is now handled in the Password Management region above

# Read existing parameters from parameters.json
$ParametersContent = Get-Content $ParametersFile | ConvertFrom-Json
$ExistingParams = @{}

# Check which parameters have values in parameters.json
foreach ($param in $ParametersContent.parameters.PSObject.Properties) {
    if ($param.Value.value -ne $null -and $param.Value.value -ne "") {
        $ExistingParams[$param.Name] = $param.Value.value
    }
}

# Prepare deployment parameters - script parameters override parameters.json
$DeploymentParams = @{
    ResourceGroupName     = $ResourceGroupName
    TemplateFile         = $TemplateFile
    TemplateParameterFile = $ParametersFile
    Mode                 = "Incremental"
}

# Add location parameter (script parameter takes precedence)
$DeploymentParams.location = $Location

# Add VM name parameter (script parameter takes precedence)
$DeploymentParams.virtualMachines_squidder_name = $VMName

# Add admin username parameter
$DeploymentParams.adminUsername = $AdminUsername

# Add admin password parameter
$DeploymentParams.adminPassword = $AdminPassword

Write-Host "Using parameters:" -ForegroundColor Yellow
Write-Host "  Location: $Location $(if ($ExistingParams.location -and $ExistingParams.location -ne $Location) { "(overriding parameters.json: $($ExistingParams.location))" })" -ForegroundColor White
Write-Host "  VM Name: $VMName $(if ($ExistingParams.virtualMachines_squidder_name -and $ExistingParams.virtualMachines_squidder_name -ne $VMName) { "(overriding parameters.json: $($ExistingParams.virtualMachines_squidder_name))" })" -ForegroundColor White
Write-Host "  Admin Username: $AdminUsername" -ForegroundColor White

Write-Host "Validating ARM template..." -ForegroundColor Yellow
try {
    $ValidationResult = Test-AzResourceGroupDeployment @DeploymentParams
    if ($ValidationResult) {
        Write-Error "Template validation failed: $($ValidationResult | ConvertTo-Json -Depth 3)"
    }
    Write-Host "Template validation successful" -ForegroundColor Green
}
catch {
    Write-Error "Template validation error: $($_.Exception.Message)"
}

# Check if deployment already exists and is successful
$DeploymentName = "squidder-deployment-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$ExistingVM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction SilentlyContinue

if ($ExistingVM) {
    Write-Host "VM '$VMName' already exists. Checking status..." -ForegroundColor Yellow
    $VMStatus = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status
    $PowerState = ($VMStatus.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus
    Write-Host "VM Power State: $PowerState" -ForegroundColor Yellow
    
    if ($PowerState -ne "VM running") {
        Write-Host "Starting VM..." -ForegroundColor Yellow
        Start-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -NoWait
    }
}
else {
    Write-Host "Deploying ARM template..." -ForegroundColor Yellow
    try {
        $Deployment = New-AzResourceGroupDeployment @DeploymentParams -Name $DeploymentName -Verbose
        
        if ($Deployment.ProvisioningState -eq "Succeeded") {
            Write-Host "ARM template deployment completed successfully" -ForegroundColor Green
        }
        else {
            Write-Error "Deployment failed with state: $($Deployment.ProvisioningState)"
        }
    }
    catch {
        Write-Error "Deployment failed: $($_.Exception.Message)"
    }
}
#endregion

#region Squid Installation and Configuration
Write-Host "`n--- Squid Proxy Configuration ---" -ForegroundColor Green

# Get VM public IP
$PublicIP = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName | Where-Object { $_.Name -like "*squidder*" }
if (-not $PublicIP -or -not $PublicIP.IpAddress) {
    Write-Error "Could not retrieve public IP address for the VM"
}

$VMPublicIP = $PublicIP.IpAddress
Write-Host "VM Public IP: $VMPublicIP" -ForegroundColor Yellow

# Parse allowed networks for Squid configuration
$AllowedNetworksList = $AllowedNetworks -split "," | ForEach-Object { $_.Trim() }

# Build Squid ACL configuration
$SquidACLs = @()
$SquidAllowRules = @()

$aclIndex = 1
foreach ($network in $AllowedNetworksList) {
    $aclName = "allowed_net_$aclIndex"
    $SquidACLs += "acl $aclName src $network"
    $SquidAllowRules += "http_access allow $aclName"
    $aclIndex++
}

# Squid installation and configuration script
$SquidInstallScript = @"
#!/bin/bash
set -e

echo "Installing Squid proxy..."
sudo apt-get update -y
sudo apt-get install -y squid

echo "Configuring Squid..."
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.backup

# Create custom squid configuration
sudo tee /etc/squid/squid.conf > /dev/null <<EOF
# Squid Proxy Configuration
# Generated by Azure Squid Configuration Script

# HTTP port configuration
http_port $SquidPort

# Access Control Lists (ACLs)
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10

# Custom allowed networks
$($SquidACLs -join "`n")

# SSL ports
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT

# Deny requests to certain unsafe ports
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

# Allow localhost manager access
http_access allow localhost manager
http_access deny manager

# Allow configured networks
$($SquidAllowRules -join "`n")

# Allow local networks
http_access allow localnet
http_access allow localhost

# Deny all other access
http_access deny all

# Logging
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log

# Cache settings
cache_dir ufs /var/spool/squid 100 16 256
coredump_dir /var/spool/squid

# Memory settings
cache_mem 64 MB
maximum_object_size_in_memory 1 MB
maximum_object_size 100 MB

refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
EOF

echo "Starting Squid service..."
sudo systemctl enable squid
sudo systemctl restart squid
sudo systemctl status squid

echo "Opening firewall for Squid..."
sudo ufw allow $SquidPort/tcp || true

echo "Squid installation and configuration completed"
"@

# Execute Squid installation via Azure VM Run Command
Write-Host "Installing and configuring Squid on the VM..." -ForegroundColor Yellow
try {
    $RunCommandResult = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunShellScript' -ScriptString $SquidInstallScript

    if ($RunCommandResult.Status -eq "Succeeded") {
        Write-Host "Squid installation completed successfully" -ForegroundColor Green
        Write-Host "Installation output:" -ForegroundColor Cyan
        $RunCommandResult.Value | ForEach-Object { Write-Host $_.Message -ForegroundColor White }
    }
    else {
        Write-Warning "Squid installation may have failed. Status: $($RunCommandResult.Status)"
        $RunCommandResult.Value | ForEach-Object { Write-Host $_.Message -ForegroundColor Red }
    }
}
catch {
    Write-Error "Failed to install Squid: $($_.Exception.Message)"
}

# Wait for Squid to be ready
Write-Host "Waiting for Squid service to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 30
#endregion

#region Proxy Testing
Write-Host "`n--- Proxy Functionality Testing ---" -ForegroundColor Green

$ProxyUrl = "http://${VMPublicIP}:$SquidPort"
Write-Host "Testing proxy at: $ProxyUrl" -ForegroundColor Yellow

# Function to test HTTP/HTTPS through proxy
function Test-ProxyConnection {
    param(
        [string]$Url,
        [string]$ProxyServer,
        [string]$Protocol
    )
    
    try {
        Write-Host "Testing $Protocol connection to $Url via proxy..." -ForegroundColor Yellow
        
        $WebRequest = [System.Net.WebRequest]::Create($Url)
        $WebRequest.Proxy = New-Object System.Net.WebProxy($ProxyServer)
        $WebRequest.Timeout = 30000
        
        $Response = $WebRequest.GetResponse()
        $StatusCode = $Response.StatusCode
        $ContentLength = $Response.ContentLength
        $Response.Close()
        
        Write-Host "✓ $Protocol test successful - Status: $StatusCode, Content-Length: $ContentLength" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "✗ $Protocol test failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Test HTTP connection
$HttpTest = Test-ProxyConnection -Url "http://google.com" -ProxyServer $ProxyUrl -Protocol "HTTP"

# Test HTTPS connection
$HttpsTest = Test-ProxyConnection -Url "https://google.com" -ProxyServer $ProxyUrl -Protocol "HTTPS"

# Additional connectivity test using PowerShell's Invoke-WebRequest
Write-Host "`nTesting with PowerShell Invoke-WebRequest..." -ForegroundColor Yellow
try {
    $ProxyObject = New-Object System.Net.WebProxy($ProxyUrl)
    $HttpResponse = Invoke-WebRequest -Uri "http://google.com" -Proxy $ProxyUrl -TimeoutSec 30 -UseBasicParsing
    Write-Host "✓ PowerShell HTTP test successful - Status: $($HttpResponse.StatusCode)" -ForegroundColor Green
}
catch {
    Write-Host "✗ PowerShell HTTP test failed: $($_.Exception.Message)" -ForegroundColor Red
}

try {
    $HttpsResponse = Invoke-WebRequest -Uri "https://google.com" -Proxy $ProxyUrl -TimeoutSec 30 -UseBasicParsing
    Write-Host "✓ PowerShell HTTPS test successful - Status: $($HttpsResponse.StatusCode)" -ForegroundColor Green
}
catch {
    Write-Host "✗ PowerShell HTTPS test failed: $($_.Exception.Message)" -ForegroundColor Red
}
#endregion

#region NSG SSH Port Management
Write-Host "`n--- NSG SSH Port Management ---" -ForegroundColor Green

# Get NSG
$NSGName = $ExistingParams.networkSecurityGroups_squidder_nsg_name
if (-not $NSGName) {
    $NSGName = "squidder-nsg"  # fallback to default
}

Write-Host "Managing SSH access on NSG: $NSGName" -ForegroundColor Yellow

# Check if proxy tests were successful
if ($HttpTest -and $HttpsTest) {
    Write-Host "Proxy tests successful. Closing SSH port (22) for security..." -ForegroundColor Yellow
    
    try {
        $NSG = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $NSGName
        
        # Find and remove SSH rule
        $SSHRule = $NSG.SecurityRules | Where-Object { $_.Name -eq "SSH" -or $_.DestinationPortRange -eq "22" }
        
        if ($SSHRule) {
            foreach ($rule in $SSHRule) {
                Write-Host "Removing SSH rule: $($rule.Name)" -ForegroundColor Yellow
                $NSG = Remove-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $NSG -Name $rule.Name
            }
            
            # Apply changes
            $UpdateResult = Set-AzNetworkSecurityGroup -NetworkSecurityGroup $NSG
            
            if ($UpdateResult.ProvisioningState -eq "Succeeded") {
                Write-Host "✓ SSH port (22) has been closed for security" -ForegroundColor Green
                Write-Host "  Note: Use ChangeAdminPassword.ps1 script to temporarily open SSH when needed" -ForegroundColor Cyan
            }
            else {
                Write-Warning "Failed to close SSH port. Status: $($UpdateResult.ProvisioningState)"
            }
        }
        else {
            Write-Host "No SSH rule found to remove" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Failed to manage SSH port: $($_.Exception.Message)"
    }
}
else {
    Write-Host "Proxy tests failed. Keeping SSH port (22) open for troubleshooting" -ForegroundColor Yellow
}
#endregion

#region Summary
Write-Host "`n=== Deployment Summary ===" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host "VM Name: $VMName" -ForegroundColor White
Write-Host "VM Public IP: $VMPublicIP" -ForegroundColor White
Write-Host "Proxy URL: $ProxyUrl" -ForegroundColor White
Write-Host "Admin Username: $AdminUsername" -ForegroundColor White

if ($HttpTest -and $HttpsTest) {
    Write-Host "`n✓ Squid proxy server is working correctly!" -ForegroundColor Green
    Write-Host "You can use this proxy server with the following settings:" -ForegroundColor Yellow
    Write-Host "  Proxy Server: $VMPublicIP" -ForegroundColor White
    Write-Host "  Port: $SquidPort" -ForegroundColor White
    Write-Host "  Protocol: HTTP/HTTPS" -ForegroundColor White
}
else {
    Write-Host "`n⚠ Some proxy tests failed. Please check the configuration." -ForegroundColor Yellow
}

Write-Host "`nTo connect to the VM via SSH:" -ForegroundColor Yellow
Write-Host "  ssh $AdminUsername@$VMPublicIP" -ForegroundColor White
Write-Host "`nTo check Squid logs:" -ForegroundColor Yellow
Write-Host "  sudo tail -f /var/log/squid/access.log" -ForegroundColor White
Write-Host "  sudo tail -f /var/log/squid/cache.log" -ForegroundColor White
#endregion

Write-Host "`n=== Script Completed ===" -ForegroundColor Cyan