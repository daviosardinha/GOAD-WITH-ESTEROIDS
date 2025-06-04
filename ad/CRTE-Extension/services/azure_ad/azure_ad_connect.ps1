# CRTE Extension for GOAD - Azure AD Connect Vulnerabilities
# This script configures Azure AD Connect vulnerabilities for CRTE attack scenarios

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
$LogFile = "$ScriptPath\azure_ad_connect_vulnerabilities.log"

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

# Function to configure Azure AD Connect server with stored credentials
function Set-AzureADConnectCredentials {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ADConnectServerIP,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$ADSyncAccount,
        
        [Parameter(Mandatory=$true)]
        [string]$ADSyncPassword
    )
    
    Write-Log "Configuring Azure AD Connect credentials on $ADConnectServerIP"
    
    # Create a PowerShell session to the Azure AD Connect server
    $session = New-PSSession -ComputerName $ADConnectServerIP -Credential $Credential
    
    try {
        # Create a script block to configure Azure AD Connect credentials
        $scriptBlock = {
            param($ADSyncAccount, $ADSyncPassword)
            
            # Create directory structure to simulate Azure AD Connect
            $adConnectDir = "C:\Program Files\Microsoft Azure AD Sync"
            $adConnectDataDir = "$adConnectDir\Data"
            
            if (-not (Test-Path $adConnectDir)) {
                New-Item -Path $adConnectDir -ItemType Directory -Force | Out-Null
            }
            
            if (-not (Test-Path $adConnectDataDir)) {
                New-Item -Path $adConnectDataDir -ItemType Directory -Force | Out-Null
            }
            
            # Create a simulated ADSync.mdf file with credentials
            $credentialsFile = "$adConnectDataDir\ADSync.mdf"
            
            # Create a simple text file with the credentials (in a real environment, this would be an encrypted database)
            $credentialsContent = @"
Azure AD Connect Credentials
===========================
Sync Account: $ADSyncAccount
Password: $ADSyncPassword
===========================
This file simulates the Azure AD Connect database that stores credentials.
In a real environment, these credentials would be stored in an encrypted SQL database.
For CRTE practice purposes, this file represents the vulnerable storage of credentials.
"@
            
            Set-Content -Path $credentialsFile -Value $credentialsContent
            
            # Create a registry key to simulate Azure AD Connect installation
            $registryPath = "HKLM:\SOFTWARE\Microsoft\Azure AD Connect"
            
            if (-not (Test-Path $registryPath)) {
                New-Item -Path $registryPath -Force | Out-Null
            }
            
            New-ItemProperty -Path $registryPath -Name "Install Path" -Value $adConnectDir -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $registryPath -Name "Version" -Value "1.6.4.0" -PropertyType String -Force | Out-Null
            
            # Create a scheduled task to simulate the ADSync service
            $taskName = "ADSync"
            $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            
            if ($taskExists) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            }
            
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command `"& {Write-EventLog -LogName Application -Source 'ADSync' -EventId 1 -Message 'ADSync cycle completed'}`""
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30)
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal
            
            # Create an event log source for ADSync
            if (-not ([System.Diagnostics.EventLog]::SourceExists("ADSync"))) {
                New-EventLog -LogName Application -Source "ADSync"
            }
            
            Write-Output "Successfully configured Azure AD Connect credentials on server"
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $ADSyncAccount, $ADSyncPassword
        
        Write-Log "Azure AD Connect credentials configured on $ADConnectServerIP"
    }
    catch {
        Write-Log "Failed to configure Azure AD Connect credentials: $_" -Error
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
Write-Log "Starting Azure AD Connect vulnerability configuration for CRTE extension..."

# Create credential object for GOAD admin
$securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)

# Configure Azure AD Connect credentials on us-adconnect server
# This simulates the Azure AD Connect credential extraction vulnerability
Set-AzureADConnectCredentials -ADConnectServerIP "192.168.56.28" -Credential $credential -ADSyncAccount "sync_admin@kingandqueen.onmicrosoft.com" -ADSyncPassword "SyncPassword123!"

Write-Log "Azure AD Connect vulnerability configuration completed successfully"
