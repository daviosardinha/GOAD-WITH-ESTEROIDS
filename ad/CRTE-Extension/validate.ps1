# CRTE Extension for GOAD - Validation Script
# This script validates the CRTE extension installation on a standard GOAD deployment

param(
    [Parameter(Mandatory=$false)]
    [string]$GoadDcIp = "192.168.56.10",
    
    [Parameter(Mandatory=$false)]
    [string]$GoadAdminUser = "Administrator",
    
    [Parameter(Mandatory=$false)]
    [string]$GoadAdminPassword = "Password123!"
)

# Script variables
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile = "$ScriptPath\validation_results.log"
$ErrorLogFile = "$ScriptPath\validation_errors.log"

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
        Add-Content -Path $ErrorLogFile -Value $LogMessage
    } else {
        Write-Host $LogMessage -ForegroundColor Green
        Add-Content -Path $LogFile -Value $LogMessage
    }
}

# Function to validate domain structure
function Test-DomainStructure {
    Write-Log "Validating domain structure..."
    
    # Define expected domains and their controllers
    $domains = @{
        "kingandqueen.local" = "192.168.56.10"
        "north.kingandqueen.local" = "192.168.56.11"
        "bastion.local" = "192.168.56.20"
        "production.local" = "192.168.56.30"
        "db.local" = "192.168.56.40"
        "dbvendor.local" = "192.168.56.50"
        "usvendor.local" = "192.168.56.60"
    }
    
    $success = $true
    
    # Check if domain controllers are reachable
    foreach ($domain in $domains.Keys) {
        $dcIp = $domains[$domain]
        
        if (Test-Connection -ComputerName $dcIp -Count 1 -Quiet) {
            Write-Log "Domain controller for $domain at $dcIp is reachable"
        } else {
            Write-Log "Domain controller for $domain at $dcIp is not reachable" -Error
            $success = $false
        }
    }
    
    if ($success) {
        Write-Log "Domain structure validation completed successfully"
    } else {
        Write-Log "Domain structure validation completed with errors" -Error
    }
    
    return $success
}

# Function to validate trust relationships
function Test-TrustRelationships {
    Write-Log "Validating trust relationships..."
    
    # Create credential object for GOAD admin
    $securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)
    
    # Define expected trusts
    $trusts = @(
        @{
            "TrustingDomain" = "kingandqueen.local"
            "TrustedDomain" = "bastion.local"
            "TrustType" = "External"
            "TrustDirection" = "Outbound"
            "DcIp" = "192.168.56.10"
        },
        @{
            "TrustingDomain" = "bastion.local"
            "TrustedDomain" = "production.local"
            "TrustType" = "External"
            "TrustDirection" = "Outbound"
            "DcIp" = "192.168.56.20"
        },
        @{
            "TrustingDomain" = "north.kingandqueen.local"
            "TrustedDomain" = "db.local"
            "TrustType" = "External"
            "TrustDirection" = "Outbound"
            "DcIp" = "192.168.56.11"
        },
        @{
            "TrustingDomain" = "db.local"
            "TrustedDomain" = "dbvendor.local"
            "TrustType" = "External"
            "TrustDirection" = "Bidirectional"
            "DcIp" = "192.168.56.40"
        },
        @{
            "TrustingDomain" = "north.kingandqueen.local"
            "TrustedDomain" = "usvendor.local"
            "TrustType" = "External"
            "TrustDirection" = "Outbound"
            "DcIp" = "192.168.56.11"
        }
    )
    
    $success = $true
    
    # Check each trust
    foreach ($trust in $trusts) {
        try {
            # Create a PowerShell session to the domain controller
            if (Test-Connection -ComputerName $trust.DcIp -Count 1 -Quiet) {
                $session = New-PSSession -ComputerName $trust.DcIp -Credential $credential -ErrorAction Stop
                
                # Create a script block to check the trust
                $scriptBlock = {
                    param($TrustingDomain, $TrustedDomain)
                    
                    # Check if the trust exists
                    $trustList = nltest /domain_trusts
                    $trustExists = $trustList | Where-Object { $_ -match $TrustedDomain }
                    
                    if ($trustExists) {
                        return @{
                            "Success" = $true
                            "Message" = "Trust from $TrustingDomain to $TrustedDomain exists"
                        }
                    } else {
                        return @{
                            "Success" = $false
                            "Message" = "Trust from $TrustingDomain to $TrustedDomain does not exist"
                        }
                    }
                }
                
                # Execute the script block on the remote server
                $result = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $trust.TrustingDomain, $trust.TrustedDomain
                
                if ($result.Success) {
                    Write-Log $result.Message
                } else {
                    Write-Log $result.Message -Error
                    $success = $false
                }
                
                # Close the PowerShell session
                Remove-PSSession $session
            } else {
                Write-Log "Cannot connect to domain controller at $($trust.DcIp) to validate trust from $($trust.TrustingDomain) to $($trust.TrustedDomain)" -Error
                $success = $false
            }
        } catch {
            Write-Log "Error validating trust from $($trust.TrustingDomain) to $($trust.TrustedDomain): $_" -Error
            $success = $false
        }
    }
    
    if ($success) {
        Write-Log "Trust relationship validation completed successfully"
    } else {
        Write-Log "Trust relationship validation completed with errors" -Error
    }
    
    return $success
}

# Function to validate user accounts
function Test-UserAccounts {
    Write-Log "Validating user accounts..."
    
    # Create credential object for GOAD admin
    $securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)
    
    # Define expected users
    $users = @(
        @{
            "Domain" = "kingandqueen.local"
            "DcIp" = "192.168.56.10"
            "Username" = "crteadmin"
        },
        @{
            "Domain" = "kingandqueen.local"
            "DcIp" = "192.168.56.10"
            "Username" = "svc_sql"
        },
        @{
            "Domain" = "north.kingandqueen.local"
            "DcIp" = "192.168.56.11"
            "Username" = "regular_user"
        },
        @{
            "Domain" = "north.kingandqueen.local"
            "DcIp" = "192.168.56.11"
            "Username" = "helpdesk_admin"
        },
        @{
            "Domain" = "north.kingandqueen.local"
            "DcIp" = "192.168.56.11"
            "Username" = "svc_exchange"
        },
        @{
            "Domain" = "north.kingandqueen.local"
            "DcIp" = "192.168.56.11"
            "Username" = "user_asrep"
        },
        @{
            "Domain" = "bastion.local"
            "DcIp" = "192.168.56.20"
            "Username" = "bastion_admin"
        },
        @{
            "Domain" = "db.local"
            "DcIp" = "192.168.56.40"
            "Username" = "db_admin"
        },
        @{
            "Domain" = "db.local"
            "DcIp" = "192.168.56.40"
            "Username" = "sql_service"
        }
    )
    
    $success = $true
    
    # Check each user
    foreach ($user in $users) {
        try {
            # Create a PowerShell session to the domain controller
            if (Test-Connection -ComputerName $user.DcIp -Count 1 -Quiet) {
                $session = New-PSSession -ComputerName $user.DcIp -Credential $credential -ErrorAction Stop
                
                # Create a script block to check the user
                $scriptBlock = {
                    param($Username)
                    
                    # Import the ActiveDirectory module
                    Import-Module ActiveDirectory
                    
                    # Check if the user exists
                    try {
                        $adUser = Get-ADUser -Identity $Username -ErrorAction Stop
                        return @{
                            "Success" = $true
                            "Message" = "User $Username exists"
                        }
                    } catch {
                        return @{
                            "Success" = $false
                            "Message" = "User $Username does not exist"
                        }
                    }
                }
                
                # Execute the script block on the remote server
                $result = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $user.Username
                
                if ($result.Success) {
                    Write-Log $result.Message
                } else {
                    Write-Log $result.Message -Error
                    $success = $false
                }
                
                # Close the PowerShell session
                Remove-PSSession $session
            } else {
                Write-Log "Cannot connect to domain controller at $($user.DcIp) to validate user $($user.Username)" -Error
                $success = $false
            }
        } catch {
            Write-Log "Error validating user $($user.Username): $_" -Error
            $success = $false
        }
    }
    
    if ($success) {
        Write-Log "User account validation completed successfully"
    } else {
        Write-Log "User account validation completed with errors" -Error
    }
    
    return $success
}

# Function to validate vulnerabilities
function Test-Vulnerabilities {
    Write-Log "Validating vulnerabilities..."
    
    # This is a simplified validation that checks if the vulnerability scripts exist
    $vulnerabilityScripts = @(
        "$ScriptPath\vulnerabilities\kerberos\delegation.ps1",
        "$ScriptPath\vulnerabilities\acl\misconfigurations.ps1",
        "$ScriptPath\vulnerabilities\trusts\trust_vulnerabilities.ps1",
        "$ScriptPath\services\sql\sql_links.ps1",
        "$ScriptPath\services\azure_ad\azure_ad_connect.ps1",
        "$ScriptPath\services\exchange\exchange_vulnerabilities.ps1"
    )
    
    $success = $true
    
    foreach ($script in $vulnerabilityScripts) {
        if (Test-Path $script) {
            Write-Log "Vulnerability script $script exists"
        } else {
            Write-Log "Vulnerability script $script does not exist" -Error
            $success = $false
        }
    }
    
    if ($success) {
        Write-Log "Vulnerability validation completed successfully"
        Write-Log "Note: Full vulnerability validation requires manual testing of attack paths"
    } else {
        Write-Log "Vulnerability validation completed with errors" -Error
    }
    
    return $success
}

# Main validation process
Write-Log "Starting CRTE extension validation..."

# Clear previous log files
if (Test-Path $LogFile) {
    Remove-Item $LogFile -Force
}
if (Test-Path $ErrorLogFile) {
    Remove-Item $ErrorLogFile -Force
}

# Run validation functions
$domainSuccess = Test-DomainStructure
$trustSuccess = Test-TrustRelationships
$userSuccess = Test-UserAccounts
$vulnerabilitySuccess = Test-Vulnerabilities

# Overall validation result
if ($domainSuccess -and $trustSuccess -and $userSuccess -and $vulnerabilitySuccess) {
    Write-Log "CRTE extension validation completed successfully"
    Write-Log "All components are properly configured"
} else {
    Write-Log "CRTE extension validation completed with errors" -Error
    Write-Log "Please review the error log for details: $ErrorLogFile" -Error
}

Write-Log "For detailed validation of attack paths, please refer to the attack paths documentation"
