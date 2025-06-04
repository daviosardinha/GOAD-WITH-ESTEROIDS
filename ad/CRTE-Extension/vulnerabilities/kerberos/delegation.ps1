# CRTE Extension for GOAD - Kerberos Delegation Vulnerabilities
# This script configures Kerberos delegation vulnerabilities for CRTE attack scenarios

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
$LogFile = "$ScriptPath\kerberos_delegation.log"

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

# Function to configure unconstrained delegation
function Set-UnconstrainedDelegation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )
    
    Write-Log "Configuring unconstrained delegation for $ComputerName in domain $DomainName"
    
    # Create a PowerShell session to the domain controller
    $session = New-PSSession -ComputerName $DomainController -Credential $Credential
    
    try {
        # Create a script block to configure unconstrained delegation
        $scriptBlock = {
            param($ComputerName)
            
            # Get the computer account
            $computer = Get-ADComputer -Identity $ComputerName
            
            # Enable unconstrained delegation
            Set-ADAccountControl -Identity $computer.DistinguishedName -TrustedForDelegation $true
            
            # Verify the configuration
            $updatedComputer = Get-ADComputer -Identity $ComputerName -Properties TrustedForDelegation
            
            if ($updatedComputer.TrustedForDelegation) {
                Write-Output "Successfully configured unconstrained delegation for $ComputerName"
            } else {
                Write-Output "Failed to configure unconstrained delegation for $ComputerName"
            }
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $ComputerName
        
        Write-Log "Unconstrained delegation configured for $ComputerName in domain $DomainName"
    }
    catch {
        Write-Log "Failed to configure unconstrained delegation for $ComputerName: $_" -Error
        throw
    }
    finally {
        # Close the PowerShell session
        if ($session) {
            Remove-PSSession $session
        }
    }
}

# Function to configure constrained delegation
function Set-ConstrainedDelegation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory=$true)]
        [array]$AllowedServices
    )
    
    Write-Log "Configuring constrained delegation for $ComputerName in domain $DomainName"
    
    # Create a PowerShell session to the domain controller
    $session = New-PSSession -ComputerName $DomainController -Credential $Credential
    
    try {
        # Create a script block to configure constrained delegation
        $scriptBlock = {
            param($ComputerName, $AllowedServices)
            
            # Get the computer account
            $computer = Get-ADComputer -Identity $ComputerName
            
            # Enable constrained delegation
            Set-ADAccountControl -Identity $computer.DistinguishedName -TrustedForDelegation $false -TrustedToAuthForDelegation $true
            
            # Set the allowed services for delegation
            Set-ADComputer -Identity $ComputerName -Add @{"msDS-AllowedToDelegateTo" = $AllowedServices}
            
            # Verify the configuration
            $updatedComputer = Get-ADComputer -Identity $ComputerName -Properties "msDS-AllowedToDelegateTo"
            
            if ($updatedComputer."msDS-AllowedToDelegateTo") {
                Write-Output "Successfully configured constrained delegation for $ComputerName"
                Write-Output "Allowed services: $($updatedComputer."msDS-AllowedToDelegateTo" -join ', ')"
            } else {
                Write-Output "Failed to configure constrained delegation for $ComputerName"
            }
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $ComputerName, $AllowedServices
        
        Write-Log "Constrained delegation configured for $ComputerName in domain $DomainName"
    }
    catch {
        Write-Log "Failed to configure constrained delegation for $ComputerName: $_" -Error
        throw
    }
    finally {
        # Close the PowerShell session
        if ($session) {
            Remove-PSSession $session
        }
    }
}

# Function to configure resource-based constrained delegation (RBCD)
function Set-ResourceBasedConstrainedDelegation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetComputer,
        
        [Parameter(Mandatory=$true)]
        [string]$DelegatedComputer
    )
    
    Write-Log "Configuring resource-based constrained delegation from $DelegatedComputer to $TargetComputer in domain $DomainName"
    
    # Create a PowerShell session to the domain controller
    $session = New-PSSession -ComputerName $DomainController -Credential $Credential
    
    try {
        # Create a script block to configure RBCD
        $scriptBlock = {
            param($TargetComputer, $DelegatedComputer)
            
            # Get the computer accounts
            $target = Get-ADComputer -Identity $TargetComputer
            $delegated = Get-ADComputer -Identity $DelegatedComputer
            
            # Configure RBCD
            Set-ADComputer -Identity $target.DistinguishedName -PrincipalsAllowedToDelegateToAccount $delegated
            
            # Verify the configuration
            $updatedTarget = Get-ADComputer -Identity $TargetComputer -Properties "msDS-AllowedToActOnBehalfOfOtherIdentity"
            
            if ($updatedTarget."msDS-AllowedToActOnBehalfOfOtherIdentity") {
                Write-Output "Successfully configured RBCD from $DelegatedComputer to $TargetComputer"
            } else {
                Write-Output "Failed to configure RBCD from $DelegatedComputer to $TargetComputer"
            }
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $TargetComputer, $DelegatedComputer
        
        Write-Log "RBCD configured from $DelegatedComputer to $TargetComputer in domain $DomainName"
    }
    catch {
        Write-Log "Failed to configure RBCD from $DelegatedComputer to $TargetComputer: $_" -Error
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
Write-Log "Starting Kerberos delegation vulnerability configuration for CRTE extension..."

# Create credential object for GOAD admin
$securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)

# 1. Configure unconstrained delegation for Exchange server in north.kingandqueen.local
# This simulates the us-exchange server in us.techcorp.local
Set-UnconstrainedDelegation -DomainController "192.168.56.11" -DomainName "north.kingandqueen.local" -Credential $credential -ComputerName "EXCHANGE"

# 2. Configure constrained delegation for SQL server in north.kingandqueen.local
# This simulates the us-mssql server in us.techcorp.local
$allowedServices = @(
    "CIFS/DC01.kingandqueen.local",
    "LDAP/DC01.kingandqueen.local",
    "HOST/DC01.kingandqueen.local"
)
Set-ConstrainedDelegation -DomainController "192.168.56.11" -DomainName "north.kingandqueen.local" -Credential $credential -ComputerName "SQL" -AllowedServices $allowedServices

# 3. Configure resource-based constrained delegation (RBCD) from Web server to DC in north.kingandqueen.local
# This simulates the RBCD vulnerability in us.techcorp.local
Set-ResourceBasedConstrainedDelegation -DomainController "192.168.56.11" -DomainName "north.kingandqueen.local" -Credential $credential -TargetComputer "DC02" -DelegatedComputer "WEB"

Write-Log "Kerberos delegation vulnerability configuration completed successfully"
