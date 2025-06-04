# CRTE Extension for GOAD - Trust Relationship Vulnerabilities
# This script configures trust relationship vulnerabilities for CRTE attack scenarios

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
$LogFile = "$ScriptPath\trust_vulnerabilities.log"

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

# Function to configure SID filtering vulnerability
function Disable-SIDFiltering {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$TrustingDomain,
        
        [Parameter(Mandatory=$true)]
        [string]$TrustedDomain
    )
    
    Write-Log "Disabling SID filtering for trust between $TrustingDomain and $TrustedDomain"
    
    # Create a PowerShell session to the domain controller
    $session = New-PSSession -ComputerName $DomainController -Credential $Credential
    
    try {
        # Create a script block to disable SID filtering
        $scriptBlock = {
            param($TrustingDomain, $TrustedDomain)
            
            # Disable SID filtering using netdom command
            $result = netdom trust $TrustingDomain /domain:$TrustedDomain /quarantine:no
            
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Successfully disabled SID filtering for trust between $TrustingDomain and $TrustedDomain"
            } else {
                Write-Output "Failed to disable SID filtering: $result"
            }
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $TrustingDomain, $TrustedDomain
        
        Write-Log "SID filtering disabled for trust between $TrustingDomain and $TrustedDomain"
    }
    catch {
        Write-Log "Failed to disable SID filtering: $_" -Error
        throw
    }
    finally {
        # Close the PowerShell session
        if ($session) {
            Remove-PSSession $session
        }
    }
}

# Function to enable SID history for a trust
function Enable-SIDHistory {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$TrustingDomain,
        
        [Parameter(Mandatory=$true)]
        [string]$TrustedDomain
    )
    
    Write-Log "Enabling SID history for trust between $TrustingDomain and $TrustedDomain"
    
    # Create a PowerShell session to the domain controller
    $session = New-PSSession -ComputerName $DomainController -Credential $Credential
    
    try {
        # Create a script block to enable SID history
        $scriptBlock = {
            param($TrustingDomain, $TrustedDomain)
            
            # Enable SID history using netdom command
            $result = netdom trust $TrustingDomain /domain:$TrustedDomain /enablesidhistory:yes
            
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Successfully enabled SID history for trust between $TrustingDomain and $TrustedDomain"
            } else {
                Write-Output "Failed to enable SID history: $result"
            }
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $TrustingDomain, $TrustedDomain
        
        Write-Log "SID history enabled for trust between $TrustingDomain and $TrustedDomain"
    }
    catch {
        Write-Log "Failed to enable SID history: $_" -Error
        throw
    }
    finally {
        # Close the PowerShell session
        if ($session) {
            Remove-PSSession $session
        }
    }
}

# Function to add SID history to a user
function Add-SIDHistory {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        
        [Parameter(Mandatory=$true)]
        [string]$SourceDomain,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain,
        
        [Parameter(Mandatory=$true)]
        [string]$SourceSID
    )
    
    Write-Log "Adding SID history to user $UserName in domain $TargetDomain"
    
    # Create a PowerShell session to the domain controller
    $session = New-PSSession -ComputerName $DomainController -Credential $Credential
    
    try {
        # Create a script block to add SID history
        $scriptBlock = {
            param($UserName, $SourceDomain, $TargetDomain, $SourceSID)
            
            # Add SID history using DSAdd command
            $result = & dsadd user "CN=$UserName,CN=Users,DC=$TargetDomain,DC=local" -sid_history $SourceSID
            
            if ($LASTEXITCODE -eq 0) {
                Write-Output "Successfully added SID history to user $UserName"
            } else {
                Write-Output "Failed to add SID history: $result"
            }
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $UserName, $SourceDomain, $TargetDomain, $SourceSID
        
        Write-Log "SID history added to user $UserName in domain $TargetDomain"
    }
    catch {
        Write-Log "Failed to add SID history: $_" -Error
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
Write-Log "Starting trust relationship vulnerability configuration for CRTE extension..."

# Create credential object for GOAD admin
$securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)

# 1. Disable SID filtering between bastion.local and production.local
# This enables SID history abuse across the trust
Disable-SIDFiltering -DomainController "192.168.56.20" -Credential $credential -TrustingDomain "bastion.local" -TrustedDomain "production.local"

# 2. Enable SID history for trust between db.local and dbvendor.local
# This enables SID history attacks
Enable-SIDHistory -DomainController "192.168.56.40" -Credential $credential -TrustingDomain "db.local" -TrustedDomain "dbvendor.local"

# 3. Add SID history to a user in dbvendor.local
# This simulates a compromised user with SID history from db.local
Add-SIDHistory -DomainController "192.168.56.50" -Credential $credential -UserName "db_admin" -SourceDomain "db" -TargetDomain "dbvendor" -SourceSID "S-1-5-21-3263068140-2042698922-2891547269-500"

Write-Log "Trust relationship vulnerability configuration completed successfully"
