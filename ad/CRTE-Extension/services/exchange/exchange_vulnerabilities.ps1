# CRTE Extension for GOAD - Exchange Server Vulnerabilities
# This script configures Exchange Server vulnerabilities for CRTE attack scenarios

param(
    [Parameter(Mandatory=$true)]
    [string]$GoadDcIp,
    
    [Parameter(Mandatory=$true)]
    [string]$GoadAdminUser,
    
    [Parameter(Mandatory=$true)]
    [string]$GoadAdminPassword
)

# Script variables
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile = "$ScriptPath\exchange_vulnerabilities.log"

# Function to write to log file
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [switch]$Error
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] $Message"
    
    if ($Error) {
        Write-Host $LogMessage -ForegroundColor Red
    } else {
        Write-Host $LogMessage -ForegroundColor Green
    }
    
    Add-Content -Path $LogFile -Value $LogMessage
}

# Function to configure Exchange server with vulnerable permissions
function Set-ExchangeVulnerablePermissions {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ExchangeServerIP,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetUser
    )
    
    Write-Log "Configuring Exchange server vulnerable permissions on $ExchangeServerIP"
    
    # Create a PowerShell session to the Exchange server
    $session = New-PSSession -ComputerName $ExchangeServerIP -Credential $Credential
    
    try {
        # Create a script block to configure Exchange server permissions
        $scriptBlock = {
            param($TargetUser)
            
            # Create directory structure to simulate Exchange server
            $exchangeDir = "C:\Program Files\Microsoft\Exchange Server\V15"
            $exchangeBinDir = "$exchangeDir\Bin"
            
            if (-not (Test-Path $exchangeDir)) {
                New-Item -Path $exchangeDir -ItemType Directory -Force | Out-Null
            }
            
            if (-not (Test-Path $exchangeBinDir)) {
                New-Item -Path $exchangeBinDir -ItemType Directory -Force | Out-Null
            }
            
            # Create a simulated Exchange PowerShell module
            $exchangeModuleDir = "$exchangeDir\Scripts"
            
            if (-not (Test-Path $exchangeModuleDir)) {
                New-Item -Path $exchangeModuleDir -ItemType Directory -Force | Out-Null
            }
            
            # Create a simulated Exchange Management Shell script
            $exchangeShellScript = "$exchangeModuleDir\Exchange.ps1"
            
            $exchangeShellContent = @"
# Simulated Exchange Management Shell
Write-Host "Exchange Management Shell (simulated for CRTE practice)"
Write-Host "This is a simulated environment for practicing Exchange-related attacks."
"@
            
            Set-Content -Path $exchangeShellScript -Value $exchangeShellContent
            
            # Create a registry key to simulate Exchange server installation
            $registryPath = "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15"
            
            if (-not (Test-Path $registryPath)) {
                New-Item -Path $registryPath -Force | Out-Null
            }
            
            New-ItemProperty -Path $registryPath -Name "InstallPath" -Value $exchangeDir -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $registryPath -Name "MsiProductMajor" -Value 15 -PropertyType DWord -Force | Out-Null
            
            # Create a file to document the vulnerable permissions
            $vulnerablePermissionsFile = "$exchangeDir\VulnerablePermissions.txt"
            
            $vulnerablePermissionsContent = @"
Exchange Server Vulnerable Permissions
=====================================
User: $TargetUser
Permissions: Organization Management role group membership

This file simulates the vulnerable permissions configuration in Exchange.
In a real environment, these permissions would be configured in Active Directory.
For CRTE practice purposes, this file represents the vulnerable permissions.

Attack paths:
1. Use Organization Management role group membership to gain elevated privileges
2. Use Exchange privileges to modify ACLs in Active Directory
3. Use Exchange privileges to execute arbitrary code on the Exchange server
"@
            
            Set-Content -Path $vulnerablePermissionsFile -Value $vulnerablePermissionsContent
            
            # Create a scheduled task to simulate the Exchange services
            $taskName = "MSExchangeServiceHost"
            $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            
            if ($taskExists) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            }
            
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command `"& {Write-EventLog -LogName Application -Source 'MSExchange' -EventId 1 -Message 'Exchange service running'}`""
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal
            
            # Create an event log source for Exchange
            if (-not ([System.Diagnostics.EventLog]::SourceExists("MSExchange"))) {
                New-EventLog -LogName Application -Source "MSExchange"
            }
            
            Write-Output "Successfully configured Exchange server vulnerable permissions"
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $TargetUser
        
        Write-Log "Exchange server vulnerable permissions configured on $ExchangeServerIP"
    }
    catch {
        Write-Log "Failed to configure Exchange server vulnerable permissions: $_" -Error
        throw
    }
    finally {
        # Close the PowerShell session
        if ($session) {
            Remove-PSSession $session
        }
    }
}

# Main script execution
Write-Log "Starting Exchange server vulnerability configuration for CRTE extension..."

# Create credential object for GOAD admin
$securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)

# Configure Exchange server vulnerable permissions
# This simulates the Exchange server privilege escalation vulnerability
Set-ExchangeVulnerablePermissions -ExchangeServerIP "192.168.56.22" -Credential $credential -TargetUser "regular_user"

Write-Log "Exchange server vulnerability configuration completed successfully"
