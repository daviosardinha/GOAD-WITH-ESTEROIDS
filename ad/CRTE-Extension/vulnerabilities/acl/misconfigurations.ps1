# CRTE Extension for GOAD - ACL Misconfigurations
# This script configures ACL misconfigurations for CRTE attack scenarios

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
$LogFile = "$ScriptPath\acl_misconfigurations.log"

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

# Function to configure GenericAll permission on a group
function Set-GenericAllPermission {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetGroup,
        
        [Parameter(Mandatory=$true)]
        [string]$PrincipalName
    )
    
    Write-Log "Configuring GenericAll permission for $PrincipalName on $TargetGroup in domain $DomainName"
    
    # Create a PowerShell session to the domain controller
    $session = New-PSSession -ComputerName $DomainController -Credential $Credential
    
    try {
        # Create a script block to configure GenericAll permission
        $scriptBlock = {
            param($TargetGroup, $PrincipalName)
            
            # Import the ActiveDirectory module
            Import-Module ActiveDirectory
            
            # Get the target group
            $group = Get-ADGroup -Identity $TargetGroup
            
            # Get the principal (user or group)
            $principal = $null
            try {
                $principal = Get-ADUser -Identity $PrincipalName
            } catch {
                try {
                    $principal = Get-ADGroup -Identity $PrincipalName
                } catch {
                    Write-Output "Principal $PrincipalName not found"
                    return
                }
            }
            
            # Get the current ACL
            $acl = Get-Acl -Path "AD:$($group.DistinguishedName)"
            
            # Create a new access rule
            $sid = New-Object System.Security.Principal.SecurityIdentifier $principal.SID
            $identity = [System.Security.Principal.IdentityReference] $sid
            $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
            $type = [System.Security.AccessControl.AccessControlType] "Allow"
            $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $inheritanceType
            
            # Add the rule to the ACL
            $acl.AddAccessRule($rule)
            
            # Set the modified ACL
            Set-Acl -Path "AD:$($group.DistinguishedName)" -AclObject $acl
            
            Write-Output "Successfully configured GenericAll permission for $PrincipalName on $TargetGroup"
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $TargetGroup, $PrincipalName
        
        Write-Log "GenericAll permission configured for $PrincipalName on $TargetGroup in domain $DomainName"
    }
    catch {
        Write-Log "Failed to configure GenericAll permission for $PrincipalName on $TargetGroup: $_" -Error
        throw
    }
    finally {
        # Close the PowerShell session
        if ($session) {
            Remove-PSSession $session
        }
    }
}

# Function to configure WriteDACL permission on a domain
function Set-WriteDACLPermission {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$PrincipalName
    )
    
    Write-Log "Configuring WriteDACL permission for $PrincipalName on domain $DomainName"
    
    # Create a PowerShell session to the domain controller
    $session = New-PSSession -ComputerName $DomainController -Credential $Credential
    
    try {
        # Create a script block to configure WriteDACL permission
        $scriptBlock = {
            param($DomainName, $PrincipalName)
            
            # Import the ActiveDirectory module
            Import-Module ActiveDirectory
            
            # Get the domain
            $domain = Get-ADDomain -Identity $DomainName
            
            # Get the principal (user or group)
            $principal = $null
            try {
                $principal = Get-ADUser -Identity $PrincipalName
            } catch {
                try {
                    $principal = Get-ADGroup -Identity $PrincipalName
                } catch {
                    Write-Output "Principal $PrincipalName not found"
                    return
                }
            }
            
            # Get the current ACL
            $acl = Get-Acl -Path "AD:$($domain.DistinguishedName)"
            
            # Create a new access rule
            $sid = New-Object System.Security.Principal.SecurityIdentifier $principal.SID
            $identity = [System.Security.Principal.IdentityReference] $sid
            $adRights = [System.DirectoryServices.ActiveDirectoryRights] "WriteDacl"
            $type = [System.Security.AccessControl.AccessControlType] "Allow"
            $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $inheritanceType
            
            # Add the rule to the ACL
            $acl.AddAccessRule($rule)
            
            # Set the modified ACL
            Set-Acl -Path "AD:$($domain.DistinguishedName)" -AclObject $acl
            
            Write-Output "Successfully configured WriteDACL permission for $PrincipalName on domain $DomainName"
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $DomainName, $PrincipalName
        
        Write-Log "WriteDACL permission configured for $PrincipalName on domain $DomainName"
    }
    catch {
        Write-Log "Failed to configure WriteDACL permission for $PrincipalName on domain $DomainName: $_" -Error
        throw
    }
    finally {
        # Close the PowerShell session
        if ($session) {
            Remove-PSSession $session
        }
    }
}

# Function to configure WriteProperty permission on a user
function Set-WritePropertyPermission {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainController,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetUser,
        
        [Parameter(Mandatory=$true)]
        [string]$PrincipalName,
        
        [Parameter(Mandatory=$true)]
        [string]$PropertyName
    )
    
    Write-Log "Configuring WriteProperty permission for $PrincipalName on $TargetUser's $PropertyName in domain $DomainName"
    
    # Create a PowerShell session to the domain controller
    $session = New-PSSession -ComputerName $DomainController -Credential $Credential
    
    try {
        # Create a script block to configure WriteProperty permission
        $scriptBlock = {
            param($TargetUser, $PrincipalName, $PropertyName)
            
            # Import the ActiveDirectory module
            Import-Module ActiveDirectory
            
            # Get the target user
            $user = Get-ADUser -Identity $TargetUser
            
            # Get the principal (user or group)
            $principal = $null
            try {
                $principal = Get-ADUser -Identity $PrincipalName
            } catch {
                try {
                    $principal = Get-ADGroup -Identity $PrincipalName
                } catch {
                    Write-Output "Principal $PrincipalName not found"
                    return
                }
            }
            
            # Get the current ACL
            $acl = Get-Acl -Path "AD:$($user.DistinguishedName)"
            
            # Create a new access rule
            $sid = New-Object System.Security.Principal.SecurityIdentifier $principal.SID
            $identity = [System.Security.Principal.IdentityReference] $sid
            $adRights = [System.DirectoryServices.ActiveDirectoryRights] "WriteProperty"
            $type = [System.Security.AccessControl.AccessControlType] "Allow"
            $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
            
            # Get the property GUID
            $propertyGuid = $null
            switch ($PropertyName) {
                "msDS-KeyCredentialLink" {
                    $propertyGuid = New-Object Guid "5b47d60f-6090-40b2-9f37-2a4de88f3063"
                }
                "servicePrincipalName" {
                    $propertyGuid = New-Object Guid "f3a64788-5306-11d1-a9c5-0000f80367c1"
                }
                default {
                    Write-Output "Property $PropertyName not supported"
                    return
                }
            }
            
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $propertyGuid, $inheritanceType
            
            # Add the rule to the ACL
            $acl.AddAccessRule($rule)
            
            # Set the modified ACL
            Set-Acl -Path "AD:$($user.DistinguishedName)" -AclObject $acl
            
            Write-Output "Successfully configured WriteProperty permission for $PrincipalName on $TargetUser's $PropertyName"
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $TargetUser, $PrincipalName, $PropertyName
        
        Write-Log "WriteProperty permission configured for $PrincipalName on $TargetUser's $PropertyName in domain $DomainName"
    }
    catch {
        Write-Log "Failed to configure WriteProperty permission for $PrincipalName on $TargetUser's $PropertyName: $_" -Error
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
Write-Log "Starting ACL misconfiguration setup for CRTE extension..."

# Create credential object for GOAD admin
$securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)

# 1. Configure GenericAll permission for helpdesk_admin on Domain Admins group in north.kingandqueen.local
# This simulates the ACL misconfiguration in us.techcorp.local
Set-GenericAllPermission -DomainController "192.168.56.11" -DomainName "north.kingandqueen.local" -Credential $credential -TargetGroup "Domain Admins" -PrincipalName "helpdesk_admin"

# 2. Configure WriteDACL permission for WebAdmins group on north.kingandqueen.local domain
# This allows for DCSync attack path
Set-WriteDACLPermission -DomainController "192.168.56.11" -DomainName "north.kingandqueen.local" -Credential $credential -PrincipalName "WebAdmins"

# 3. Configure WriteProperty permission for regular_user on svc_exchange's msDS-KeyCredentialLink property
# This enables Shadow Credentials attack
Set-WritePropertyPermission -DomainController "192.168.56.11" -DomainName "north.kingandqueen.local" -Credential $credential -TargetUser "svc_exchange" -PrincipalName "regular_user" -PropertyName "msDS-KeyCredentialLink"

# 4. Configure WriteProperty permission for SQLAdmins on svc_sql's servicePrincipalName property
# This enables Kerberoasting attack path
Set-WritePropertyPermission -DomainController $GoadDcIp -DomainName "kingandqueen.local" -Credential $credential -TargetUser "svc_sql" -PrincipalName "SQLAdmins" -PropertyName "servicePrincipalName"

Write-Log "ACL misconfiguration setup completed successfully"
