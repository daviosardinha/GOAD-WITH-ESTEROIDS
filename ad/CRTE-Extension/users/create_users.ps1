# CRTE Extension for GOAD - User and Group Creation Script
# This script creates users and groups required for CRTE attack scenarios

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
$LogFile = "$ScriptPath\user_creation.log"

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

# Function to create users in a domain
function New-CrteUsers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [array]$Users
    )
    
    Write-Log "Creating users in domain: $DomainName"
    
    # Create a PowerShell session to the domain controller
    $session = New-PSSession -ComputerName $DomainController -Credential $Credential
    
    try {
        # Create a script block to create users
        $scriptBlock = {
            param($Users, $DomainName)
            
            foreach ($user in $Users) {
                try {
                    # Create the user
                    $securePassword = ConvertTo-SecureString $user.Password -AsPlainText -Force
                    
                    $userParams = @{
                        Name = $user.Name
                        SamAccountName = $user.SamAccountName
                        UserPrincipalName = "$($user.SamAccountName)@$DomainName"
                        AccountPassword = $securePassword
                        Enabled = $true
                        PasswordNeverExpires = $true
                        Description = $user.Description
                    }
                    
                    # Add optional parameters if specified
                    if ($user.Path) {
                        $userParams.Path = $user.Path
                    }
                    
                    # Create the user
                    New-ADUser @userParams
                    
                    # Apply special configurations if needed
                    if ($user.NoPreAuth) {
                        # Configure for AS-REP Roasting (disable Kerberos pre-authentication)
                        Set-ADAccountControl -Identity $user.SamAccountName -DoesNotRequirePreAuth $true
                    }
                    
                    if ($user.ServicePrincipalNames) {
                        # Add SPNs for Kerberoasting
                        foreach ($spn in $user.ServicePrincipalNames) {
                            Set-ADUser -Identity $user.SamAccountName -ServicePrincipalNames @{Add=$spn}
                        }
                    }
                    
                    # Add user to groups if specified
                    if ($user.Groups) {
                        foreach ($group in $user.Groups) {
                            Add-ADGroupMember -Identity $group -Members $user.SamAccountName
                        }
                    }
                    
                    Write-Output "Created user: $($user.Name)"
                }
                catch {
                    Write-Output "Failed to create user $($user.Name): $_"
                }
            }
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $Users, $DomainName
        
        Write-Log "User creation completed for domain: $DomainName"
    }
    catch {
        Write-Log "Failed to create users in domain $DomainName: $_" -Error
        throw
    }
    finally {
        # Close the PowerShell session
        if ($session) {
            Remove-PSSession $session
        }
    }
}

# Function to create groups in a domain
function New-CrteGroups {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [array]$Groups
    )
    
    Write-Log "Creating groups in domain: $DomainName"
    
    # Create a PowerShell session to the domain controller
    $session = New-PSSession -ComputerName $DomainController -Credential $Credential
    
    try {
        # Create a script block to create groups
        $scriptBlock = {
            param($Groups)
            
            foreach ($group in $Groups) {
                try {
                    # Create the group
                    $groupParams = @{
                        Name = $group.Name
                        SamAccountName = $group.SamAccountName
                        GroupCategory = $group.Category
                        GroupScope = $group.Scope
                        DisplayName = $group.Name
                        Description = $group.Description
                    }
                    
                    # Add optional parameters if specified
                    if ($group.Path) {
                        $groupParams.Path = $group.Path
                    }
                    
                    # Create the group
                    New-ADGroup @groupParams
                    
                    Write-Output "Created group: $($group.Name)"
                }
                catch {
                    Write-Output "Failed to create group $($group.Name): $_"
                }
            }
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $Groups
        
        Write-Log "Group creation completed for domain: $DomainName"
    }
    catch {
        Write-Log "Failed to create groups in domain $DomainName: $_" -Error
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
Write-Log "Starting user and group creation for CRTE extension..."

# Create credential object for GOAD admin
$securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)

# Define groups for kingandqueen.local (main GOAD domain, equivalent to techcorp.local in CRTE)
$kingAndQueenGroups = @(
    @{
        Name = "Tier 0 Admins"
        SamAccountName = "Tier0Admins"
        Category = "Security"
        Scope = "Global"
        Description = "Tier 0 administrators group"
    },
    @{
        Name = "Tier 1 Admins"
        SamAccountName = "Tier1Admins"
        Category = "Security"
        Scope = "Global"
        Description = "Tier 1 administrators group"
    },
    @{
        Name = "Tier 2 Admins"
        SamAccountName = "Tier2Admins"
        Category = "Security"
        Scope = "Global"
        Description = "Tier 2 administrators group"
    }
)

# Create groups in kingandqueen.local
New-CrteGroups -DomainController $GoadDcIp -DomainName "kingandqueen.local" -Credential $credential -Groups $kingAndQueenGroups

# Define users for kingandqueen.local
$kingAndQueenUsers = @(
    @{
        Name = "CRTE Admin"
        SamAccountName = "crteadmin"
        Password = "Password123!"
        Description = "CRTE Administrator account"
        Groups = @("Domain Admins")
    },
    @{
        Name = "Service SQL"
        SamAccountName = "svc_sql"
        Password = "SqlPassword123!"
        Description = "SQL Service account"
        ServicePrincipalNames = @("MSSQLSvc/sql.kingandqueen.local:1433")
        Groups = @("Tier1Admins")
    }
)

# Create users in kingandqueen.local
New-CrteUsers -DomainController $GoadDcIp -DomainName "kingandqueen.local" -Credential $credential -Users $kingAndQueenUsers

# Define groups for north.kingandqueen.local (child domain, equivalent to us.techcorp.local in CRTE)
$northGroups = @(
    @{
        Name = "Helpdesk Admins"
        SamAccountName = "HelpdeskAdmins"
        Category = "Security"
        Scope = "Global"
        Description = "Helpdesk administrators group"
    },
    @{
        Name = "Web Admins"
        SamAccountName = "WebAdmins"
        Category = "Security"
        Scope = "Global"
        Description = "Web administrators group"
    },
    @{
        Name = "SQL Admins"
        SamAccountName = "SQLAdmins"
        Category = "Security"
        Scope = "Global"
        Description = "SQL administrators group"
    }
)

# Create groups in north.kingandqueen.local
New-CrteGroups -DomainController "192.168.56.11" -DomainName "north.kingandqueen.local" -Credential $credential -Groups $northGroups

# Define users for north.kingandqueen.local
$northUsers = @(
    @{
        Name = "Regular User"
        SamAccountName = "regular_user"
        Password = "Password123!"
        Description = "Regular user account for initial access"
    },
    @{
        Name = "Helpdesk Admin"
        SamAccountName = "helpdesk_admin"
        Password = "Password123!"
        Description = "Helpdesk administrator account"
        Groups = @("HelpdeskAdmins")
    },
    @{
        Name = "Service Exchange"
        SamAccountName = "svc_exchange"
        Password = "ExchangePassword123!"
        Description = "Exchange Service account"
        ServicePrincipalNames = @("exchangeMDB/exchange.north.kingandqueen.local")
        Groups = @("Exchange Servers")
    },
    @{
        Name = "User ASREP"
        SamAccountName = "user_asrep"
        Password = "Password123!"
        Description = "User account vulnerable to AS-REP Roasting"
        NoPreAuth = $true
    }
)

# Create users in north.kingandqueen.local
New-CrteUsers -DomainController "192.168.56.11" -DomainName "north.kingandqueen.local" -Credential $credential -Users $northUsers

# Define users for bastion.local
$bastionUsers = @(
    @{
        Name = "Bastion Admin"
        SamAccountName = "bastion_admin"
        Password = "Password123!"
        Description = "Bastion domain administrator"
        Groups = @("Domain Admins")
    }
)

# Create users in bastion.local
New-CrteUsers -DomainController "192.168.56.20" -DomainName "bastion.local" -Credential $credential -Users $bastionUsers

# Define users for db.local
$dbUsers = @(
    @{
        Name = "DB Admin"
        SamAccountName = "db_admin"
        Password = "Password123!"
        Description = "Database domain administrator"
        Groups = @("Domain Admins")
    },
    @{
        Name = "SQL Service"
        SamAccountName = "sql_service"
        Password = "SqlPassword123!"
        Description = "SQL Service account"
        ServicePrincipalNames = @("MSSQLSvc/sql.db.local:1433")
    }
)

# Create users in db.local
New-CrteUsers -DomainController "192.168.56.40" -DomainName "db.local" -Credential $credential -Users $dbUsers

Write-Log "User and group creation completed successfully"
