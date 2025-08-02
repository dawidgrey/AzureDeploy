#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Changes the administrator password for an Azure VM.

.DESCRIPTION
    This script changes the admin password for an Azure Linux VM using Azure VM Run Command.
    The new password must be supplied via command-line parameters.

.PARAMETER ResourceGroupName
    Name of the Azure resource group (default: "squidder-rg")

.PARAMETER VMName
    Name of the virtual machine (default: "squidder")

.PARAMETER AdminUsername
    Administrator username for the VM (default: "azureuser")

.PARAMETER NewPassword
    New password for the administrator account (required as SecureString)

.PARAMETER NewPasswordPlain
    New password for the administrator account (required as plain string - less secure)

.EXAMPLE
    # Using SecureString (recommended)
    $SecurePassword = ConvertTo-SecureString "MyNewPassword123!" -AsPlainText -Force
    ./ChangeAdminPassword.ps1 -NewPassword $SecurePassword

.EXAMPLE
    # Using plain text password (less secure)
    ./ChangeAdminPassword.ps1 -NewPasswordPlain "MyNewPassword123!"

.EXAMPLE
    # Custom VM parameters
    ./ChangeAdminPassword.ps1 -ResourceGroupName "my-rg" -VMName "myvm" -AdminUsername "myuser" -NewPasswordPlain "MyNewPassword123!"
#>

[CmdletBinding()]
param(
    [string]$ResourceGroupName = "squidder-us-rg",
    [string]$VMName = "squidderus", 
    [string]$AdminUsername = "azureuser",
    [string]$NewPasswordPlain
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ParametersFile = Join-Path $ScriptDir "parameters.json"

Write-Host "=== Azure VM Admin Password Change Script ===" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Yellow
Write-Host "VM Name: $VMName" -ForegroundColor Yellow
Write-Host "Admin Username: $AdminUsername" -ForegroundColor Yellow

# Get new password from environment variable, parameter, or prompt
$NewPassword = $null

if ($env:AZURE_NEW_ADMIN_PASSWORD) {
    Write-Host "Using new password from environment variable AZURE_NEW_ADMIN_PASSWORD" -ForegroundColor Green
    $NewPassword = ConvertTo-SecureString -String $env:AZURE_NEW_ADMIN_PASSWORD -AsPlainText -Force
}
elseif ($NewPasswordPlain) {
    Write-Warning "Using plain text password parameter is less secure. Consider using environment variable."
    $NewPassword = ConvertTo-SecureString -String $NewPasswordPlain -AsPlainText -Force
}
else {
    Write-Host "Environment variable AZURE_NEW_ADMIN_PASSWORD not set and no -NewPasswordPlain provided" -ForegroundColor Yellow
    $NewPassword = Read-Host "Enter new admin password for VM" -AsSecureString
    if (-not $NewPassword -or $NewPassword.Length -eq 0) {
        Write-Error "New admin password is required"
    }
}

#region Module Management
Write-Host "`n--- Checking PowerShell Modules ---" -ForegroundColor Green

$RequiredModules = @(
    @{ Name = "Az.Accounts"; MinVersion = "2.0.0" }
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
        
        # Use parameters.json values for VM identification if script parameters use defaults
        if ($VMName -eq "squidderus" -and $ExistingParams.ContainsKey("virtualMachines_squidder_name")) {
            $VMName = $ExistingParams.virtualMachines_squidder_name
            Write-Host "Using VM name from parameters.json: $VMName" -ForegroundColor Yellow
        }
        
        if ($AdminUsername -eq "azureuser" -and $ExistingParams.ContainsKey("adminUsername")) {
            $AdminUsername = $ExistingParams.adminUsername
            Write-Host "Using admin username from parameters.json: $AdminUsername" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Could not read parameters.json: $($_.Exception.Message)"
    }
}

Write-Host "Final parameters:" -ForegroundColor Green
Write-Host "  Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host "  VM Name: $VMName" -ForegroundColor White
Write-Host "  Admin Username: $AdminUsername" -ForegroundColor White
#endregion

#region Password Validation
Write-Host "`n--- Password Validation ---" -ForegroundColor Green

# Convert SecureString to plain text for validation (temporarily)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword))

# Password complexity requirements for Linux
$PasswordRequirements = @{
    MinLength = 8
    MaxLength = 123
    RequireUppercase = $true
    RequireLowercase = $true
    RequireDigit = $true
    RequireSpecialChar = $false  # Not always required for Linux
}

Write-Host "Validating password complexity..." -ForegroundColor Yellow

$ValidationErrors = @()

if ($PlainPassword.Length -lt $PasswordRequirements.MinLength) {
    $ValidationErrors += "Password must be at least $($PasswordRequirements.MinLength) characters long"
}

if ($PlainPassword.Length -gt $PasswordRequirements.MaxLength) {
    $ValidationErrors += "Password must be no more than $($PasswordRequirements.MaxLength) characters long"
}

if ($PasswordRequirements.RequireUppercase -and $PlainPassword -cnotmatch '[A-Z]') {
    $ValidationErrors += "Password must contain at least one uppercase letter"
}

if ($PasswordRequirements.RequireLowercase -and $PlainPassword -cnotmatch '[a-z]') {
    $ValidationErrors += "Password must contain at least one lowercase letter"
}

if ($PasswordRequirements.RequireDigit -and $PlainPassword -notmatch '[0-9]') {
    $ValidationErrors += "Password must contain at least one digit"
}

if ($PasswordRequirements.RequireSpecialChar -and $PlainPassword -notmatch '[^a-zA-Z0-9]') {
    $ValidationErrors += "Password must contain at least one special character"
}

# Check for common weak passwords
$WeakPasswords = @("password", "123456", "admin", "root", "user", "test")
if ($WeakPasswords -contains $PlainPassword.ToLower()) {
    $ValidationErrors += "Password is too common and weak"
}

if ($ValidationErrors.Count -gt 0) {
    Write-Host "Password validation failed:" -ForegroundColor Red
    foreach ($error in $ValidationErrors) {
        Write-Host "  ✗ $error" -ForegroundColor Red
    }
    Write-Error "Password does not meet complexity requirements"
}
else {
    Write-Host "✓ Password meets complexity requirements" -ForegroundColor Green
}

# Clear plain text password from memory
$PlainPassword = $null
[System.GC]::Collect()
#endregion

#region VM Validation
Write-Host "`n--- VM Validation ---" -ForegroundColor Green

# Check if VM exists
Write-Host "Checking if VM '$VMName' exists..." -ForegroundColor Yellow
$VM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction SilentlyContinue

if (-not $VM) {
    Write-Error "VM '$VMName' not found in resource group '$ResourceGroupName'"
}

Write-Host "VM found: $($VM.Name)" -ForegroundColor Green
Write-Host "VM Size: $($VM.HardwareProfile.VmSize)" -ForegroundColor White
Write-Host "OS Type: $($VM.StorageProfile.OsDisk.OsType)" -ForegroundColor White

if ($VM.StorageProfile.OsDisk.OsType -ne "Linux") {
    Write-Warning "This script is designed for Linux VMs. VM OS Type is: $($VM.StorageProfile.OsDisk.OsType)"
}

# Check VM power state
$VMStatus = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status
$PowerState = ($VMStatus.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus
Write-Host "VM Power State: $PowerState" -ForegroundColor Yellow

if ($PowerState -ne "VM running") {
    Write-Host "VM is not running. Starting VM..." -ForegroundColor Yellow
    Start-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -NoWait
    
    # Wait for VM to be running
    Write-Host "Waiting for VM to start..." -ForegroundColor Yellow
    do {
        Start-Sleep -Seconds 10
        $VMStatus = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status
        $PowerState = ($VMStatus.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus
        Write-Host "Current state: $PowerState" -ForegroundColor Yellow
    } while ($PowerState -ne "VM running")
}

Write-Host "VM is ready for password change" -ForegroundColor Green
#endregion

#region NSG SSH Port Management
Write-Host "`n--- Opening SSH Port for Password Change ---" -ForegroundColor Green

# Get NSG name from parameters
$NSGName = $ExistingParams.networkSecurityGroups_squidder_nsg_name
if (-not $NSGName) {
    $NSGName = "squidder-nsg"  # fallback to default
}

Write-Host "Managing SSH access on NSG: $NSGName" -ForegroundColor Yellow

try {
    $NSG = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $NSGName
    
    # Check if SSH rule already exists
    $ExistingSSHRule = $NSG.SecurityRules | Where-Object { $_.Name -eq "SSH" -or $_.DestinationPortRange -eq "22" }
    
    if (-not $ExistingSSHRule) {
        Write-Host "Opening SSH port (22) temporarily for password change..." -ForegroundColor Yellow
        
        # Add SSH rule
        $NSG = Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $NSG `
            -Name "SSH" `
            -Protocol "TCP" `
            -Direction "Inbound" `
            -Priority 300 `
            -SourceAddressPrefix "*" `
            -SourcePortRange "*" `
            -DestinationAddressPrefix "*" `
            -DestinationPortRange "22" `
            -Access "Allow" `
            -Description "Temporary SSH access for password change"
        
        # Apply changes
        $UpdateResult = Set-AzNetworkSecurityGroup -NetworkSecurityGroup $NSG
        
        if ($UpdateResult.ProvisioningState -eq "Succeeded") {
            Write-Host "✓ SSH port (22) opened temporarily" -ForegroundColor Green
            $SSHOpened = $true
        }
        else {
            Write-Warning "Failed to open SSH port. Status: $($UpdateResult.ProvisioningState)"
            $SSHOpened = $false
        }
    }
    else {
        Write-Host "SSH port (22) is already open" -ForegroundColor Green
        $SSHOpened = $false  # We didn't open it, so don't close it
    }
}
catch {
    Write-Warning "Failed to manage SSH port: $($_.Exception.Message)"
    $SSHOpened = $false
}

# Wait a moment for NSG changes to propagate
if ($SSHOpened) {
    Write-Host "Waiting for NSG changes to propagate..." -ForegroundColor Yellow
    Start-Sleep -Seconds 15
}
#endregion

#region Password Change
Write-Host "`n--- Changing Admin Password ---" -ForegroundColor Green

# Convert SecureString back to plain text for the command (done securely within the script)
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword)
$PlainNewPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# Create password change script for Linux
$PasswordChangeScript = @"
#!/bin/bash
set -e

echo "=== Changing admin password for user: $AdminUsername ==="

# Check if user exists
if ! id "$AdminUsername" &>/dev/null; then
    echo "ERROR: User '$AdminUsername' does not exist"
    exit 1
fi

# Change the password using chpasswd
echo "${AdminUsername}:${PlainNewPassword}" | sudo chpasswd

if [ `$? -eq 0 ]; then
    echo "✓ Password changed successfully for user: $AdminUsername"
    
    # Update password expiry to never expire (optional)
    sudo chage -M -1 "$AdminUsername" 2>/dev/null || true
    
    # Show user info (without sensitive data)
    echo "User account information:"
    id "$AdminUsername"
    
    # Check if user has sudo privileges
    if sudo -l -U "$AdminUsername" 2>/dev/null | grep -q "ALL"; then
        echo "✓ User has sudo privileges"
    else
        echo "ℹ User does not have sudo privileges"
    fi
    
    echo "Password change completed successfully!"
else
    echo "ERROR: Failed to change password"
    exit 1
fi
"@

Write-Host "Executing password change command on VM..." -ForegroundColor Yellow
Write-Host "This may take a few moments..." -ForegroundColor Yellow

try {
    $RunCommandResult = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -CommandId 'RunShellScript' -ScriptString $PasswordChangeScript

    if ($RunCommandResult.Status -eq "Succeeded") {
        Write-Host "✓ Password change completed successfully!" -ForegroundColor Green
        Write-Host "`nCommand Output:" -ForegroundColor Cyan
        foreach ($output in $RunCommandResult.Value) {
            if ($output.Message -and $output.Message.Trim() -ne "") {
                Write-Host "  $($output.Message)" -ForegroundColor White
            }
        }
    }
    else {
        Write-Warning "Password change may have failed. Status: $($RunCommandResult.Status)"
        Write-Host "`nCommand Output:" -ForegroundColor Yellow
        foreach ($output in $RunCommandResult.Value) {
            if ($output.Message -and $output.Message.Trim() -ne "") {
                Write-Host "  $($output.Message)" -ForegroundColor Red
            }
        }
        Write-Error "Password change failed"
    }
}
catch {
    Write-Error "Failed to execute password change command: $($_.Exception.Message)"
}
finally {
    # Clear password from memory
    $PlainNewPassword = $null
    $PasswordChangeScript = $null
    [System.GC]::Collect()
}

# Close SSH port if we opened it
if ($SSHOpened) {
    Write-Host "`n--- Closing SSH Port for Security ---" -ForegroundColor Green
    Write-Host "Password change completed. Closing SSH port (22) for security..." -ForegroundColor Yellow
    
    try {
        $NSG = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Name $NSGName
        
        # Remove SSH rule
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
            }
            else {
                Write-Warning "Failed to close SSH port. Status: $($UpdateResult.ProvisioningState)"
            }
        }
    }
    catch {
        Write-Warning "Failed to close SSH port: $($_.Exception.Message)"
    }
}
#endregion

#region Update Parameters File
Write-Host "`n--- Updating Parameters File ---" -ForegroundColor Green

if (Test-Path $ParametersFile) {
    $UpdateChoice = Read-Host "Do you want to update the password in parameters.json? (Y/N)"
    if ($UpdateChoice -match '^[Yy]') {
        try {
            # Convert SecureString to plain text for storage (consider encryption for production)
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword)
            $PasswordForStorage = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            
            # Read and update parameters.json
            $ParametersContent = Get-Content $ParametersFile | ConvertFrom-Json
            $ParametersContent.parameters.adminPassword.value = $PasswordForStorage
            
            # Write back to file
            $ParametersContent | ConvertTo-Json -Depth 10 | Set-Content $ParametersFile
            
            Write-Host "✓ Parameters file updated with new password" -ForegroundColor Green
            Write-Warning "Note: Password is stored in plain text in parameters.json. Consider using Azure Key Vault for production environments."
            
            # Clear password from memory
            $PasswordForStorage = $null
            [System.GC]::Collect()
        }
        catch {
            Write-Warning "Failed to update parameters.json: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "Parameters file not updated" -ForegroundColor Yellow
    }
}
#endregion

#region Connection Test
Write-Host "`n--- Testing New Credentials ---" -ForegroundColor Green

# Get VM public IP for connection testing
$PublicIP = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName | Where-Object { 
    $_.IpConfiguration.Id -like "*$VMName*" 
}

if ($PublicIP -and $PublicIP.IpAddress) {
    Write-Host "VM Public IP: $($PublicIP.IpAddress)" -ForegroundColor White
    Write-Host "`nYou can now test the new credentials:" -ForegroundColor Yellow
    Write-Host "  SSH Command: ssh $AdminUsername@$($PublicIP.IpAddress)" -ForegroundColor Cyan
    Write-Host "  When prompted, use the new password you just set" -ForegroundColor Cyan
    
    # Test SSH connectivity (port 22)
    Write-Host "`nTesting SSH connectivity..." -ForegroundColor Yellow
    try {
        $SSHTest = Test-NetConnection -ComputerName $PublicIP.IpAddress -Port 22 -WarningAction SilentlyContinue
        if ($SSHTest.TcpTestSucceeded) {
            Write-Host "✓ SSH port (22) is accessible" -ForegroundColor Green
        }
        else {
            Write-Host "✗ SSH port (22) is not accessible" -ForegroundColor Red
        }
    }
    catch {
        Write-Warning "Could not test SSH connectivity: $($_.Exception.Message)"
    }
}
else {
    Write-Warning "Could not retrieve VM public IP address"
}
#endregion

#region Summary
Write-Host "`n=== Password Change Summary ===" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor White
Write-Host "VM Name: $VMName" -ForegroundColor White
Write-Host "Admin Username: $AdminUsername" -ForegroundColor White
Write-Host "Password Status: ✓ Changed Successfully" -ForegroundColor Green

Write-Host "`nSecurity Notes:" -ForegroundColor Yellow
Write-Host "• Password meets complexity requirements" -ForegroundColor White
Write-Host "• Password has been set to never expire" -ForegroundColor White
Write-Host "• Consider using SSH keys for better security" -ForegroundColor White
Write-Host "• Store passwords securely (avoid plain text files)" -ForegroundColor White

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "1. Test SSH connection with new credentials" -ForegroundColor White
Write-Host "2. Update any automation scripts with new password" -ForegroundColor White
Write-Host "3. Consider setting up SSH key authentication" -ForegroundColor White

Write-Host "`nUseful Commands:" -ForegroundColor Yellow
Write-Host "  Connect via SSH: ssh $AdminUsername@[VM_PUBLIC_IP]" -ForegroundColor White
Write-Host "  Check user info: id $AdminUsername" -ForegroundColor White
Write-Host "  Test sudo access: sudo whoami" -ForegroundColor White
#endregion

Write-Host "`n=== Password Change Script Completed ===" -ForegroundColor Cyan