# CRTE Extension for GOAD - Trust Relationship Setup Script
# This script configures trust relationships between domains for CRTE scenarios

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
$LogFile = "$ScriptPath\trust_setup.log"

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

# Function to create a one-way trust
function New-OneWayTrust {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TrustingDomain,
        
        [Parameter(Mandatory=$true)]
        [string]$TrustingDomainIp,
        
        [Parameter(Mandatory=$true)]
        [string]$TrustedDomain,
        
        [Parameter(Mandatory=$true)]
        [string]$TrustedDomainIp,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$SelectiveAuthentication
    )
    
    Write-Log "Creating one-way trust from $TrustingDomain to $TrustedDomain"
    
    # Create a PowerShell session to the trusting domain controller
    $session = New-PSSession -ComputerName $TrustingDomainIp -Credential $Credential
    
    try {
        # Create a script block to establish the trust
        $scriptBlock = {
            param($TrustedDomain, $TrustedDomainIp, $SelectiveAuth)
            
            # Create DNS conditional forwarder
            Add-DnsServerConditionalForwarderZone -Name $TrustedDomain -MasterServers $TrustedDomainIp -PassThru
            
            # Create the trust
            $trustPassword = ConvertTo-SecureString "TrustPassword123!" -AsPlainText -Force
            
            if ($SelectiveAuth) {
                New-ADTrust -Name $TrustedDomain -TrustType Forest -TrustDirection Outbound -SourceName $env:USERDNSDOMAIN -TargetName $TrustedDomain -ForestTransitive $true -SelectiveAuthentication $true -TrustPassword $trustPassword
            } else {
                New-ADTrust -Name $TrustedDomain -TrustType Forest -TrustDirection Outbound -SourceName $env:USERDNSDOMAIN -TargetName $TrustedDomain -ForestTransitive $true -TrustPassword $trustPassword
            }
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $TrustedDomain, $TrustedDomainIp, $SelectiveAuthentication
        
        Write-Log "One-way trust created successfully from $TrustingDomain to $TrustedDomain"
    }
    catch {
        Write-Log "Failed to create trust from $TrustingDomain to $TrustedDomain: $_" -Error
        throw
    }
    finally {
        # Close the PowerShell session
        if ($session) {
            Remove-PSSession $session
        }
    }
}

# Function to create a two-way trust
function New-TwoWayTrust {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain1,
        
        [Parameter(Mandatory=$true)]
        [string]$Domain1Ip,
        
        [Parameter(Mandatory=$true)]
        [string]$Domain2,
        
        [Parameter(Mandatory=$true)]
        [string]$Domain2Ip,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential
    )
    
    Write-Log "Creating two-way trust between $Domain1 and $Domain2"
    
    # Create a PowerShell session to the first domain controller
    $session1 = New-PSSession -ComputerName $Domain1Ip -Credential $Credential
    
    try {
        # Create a script block to establish the trust from Domain1 to Domain2
        $scriptBlock1 = {
            param($Domain2, $Domain2Ip)
            
            # Create DNS conditional forwarder
            Add-DnsServerConditionalForwarderZone -Name $Domain2 -MasterServers $Domain2Ip -PassThru
            
            # Create the trust
            $trustPassword = ConvertTo-SecureString "TrustPassword123!" -AsPlainText -Force
            New-ADTrust -Name $Domain2 -TrustType Forest -TrustDirection Bidirectional -SourceName $env:USERDNSDOMAIN -TargetName $Domain2 -ForestTransitive $true -TrustPassword $trustPassword
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session1 -ScriptBlock $scriptBlock1 -ArgumentList $Domain2, $Domain2Ip
        
        # Create a PowerShell session to the second domain controller
        $session2 = New-PSSession -ComputerName $Domain2Ip -Credential $Credential
        
        # Create a script block to establish the trust from Domain2 to Domain1
        $scriptBlock2 = {
            param($Domain1, $Domain1Ip)
            
            # Create DNS conditional forwarder
            Add-DnsServerConditionalForwarderZone -Name $Domain1 -MasterServers $Domain1Ip -PassThru
            
            # Create the trust
            $trustPassword = ConvertTo-SecureString "TrustPassword123!" -AsPlainText -Force
            New-ADTrust -Name $Domain1 -TrustType Forest -TrustDirection Bidirectional -SourceName $env:USERDNSDOMAIN -TargetName $Domain1 -ForestTransitive $true -TrustPassword $trustPassword
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session2 -ScriptBlock $scriptBlock2 -ArgumentList $Domain1, $Domain1Ip
        
        Write-Log "Two-way trust created successfully between $Domain1 and $Domain2"
    }
    catch {
        Write-Log "Failed to create two-way trust between $Domain1 and $Domain2: $_" -Error
        throw
    }
    finally {
        # Close the PowerShell sessions
        if ($session1) {
            Remove-PSSession $session1
        }
        if ($session2) {
            Remove-PSSession $session2
        }
    }
}

# Main script execution
Write-Log "Starting trust relationship setup for CRTE extension..."

# Create credential object for GOAD admin
$securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)

# Define the trust relationships to create
# Note: kingandqueen.local is the main GOAD domain (equivalent to techcorp.local in CRTE)
# Note: north.kingandqueen.local is the child domain (equivalent to us.techcorp.local in CRTE)

# 1. One-way trust from kingandqueen.local to bastion.local
New-OneWayTrust -TrustingDomain "kingandqueen.local" -TrustingDomainIp $GoadDcIp -TrustedDomain "bastion.local" -TrustedDomainIp "192.168.56.20" -Credential $credential

# 2. One-way trust from bastion.local to production.local
New-OneWayTrust -TrustingDomain "bastion.local" -TrustingDomainIp "192.168.56.20" -TrustedDomain "production.local" -TrustedDomainIp "192.168.56.30" -Credential $credential

# 3. Selective authentication trust from north.kingandqueen.local to db.local
New-OneWayTrust -TrustingDomain "north.kingandqueen.local" -TrustingDomainIp "192.168.56.11" -TrustedDomain "db.local" -TrustedDomainIp "192.168.56.40" -Credential $credential -SelectiveAuthentication

# 4. Two-way trust between db.local and dbvendor.local
New-TwoWayTrust -Domain1 "db.local" -Domain1Ip "192.168.56.40" -Domain2 "dbvendor.local" -Domain2Ip "192.168.56.50" -Credential $credential

# 5. One-way trust from north.kingandqueen.local to usvendor.local
New-OneWayTrust -TrustingDomain "north.kingandqueen.local" -TrustingDomainIp "192.168.56.11" -TrustedDomain "usvendor.local" -TrustedDomainIp "192.168.56.60" -Credential $credential

Write-Log "Trust relationship setup completed successfully"
