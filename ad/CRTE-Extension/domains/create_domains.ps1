# CRTE Extension for GOAD - Domain Creation Script
# This script creates additional forests and domains required for CRTE scenarios

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
$LogFile = "$ScriptPath\domain_creation.log"

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

# Function to create a new forest
function New-CrteForest {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [string]$NetbiosName,
        
        [Parameter(Mandatory=$true)]
        [string]$IpAddress,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential
    )
    
    Write-Log "Creating new forest: $DomainName"
    
    # Create a PowerShell session to the GOAD DC to execute remote commands
    $session = New-PSSession -ComputerName $GoadDcIp -Credential $Credential
    
    try {
        # Create a script block to deploy a new forest
        $scriptBlock = {
            param($DomainName, $NetbiosName, $IpAddress)
            
            # Install required Windows features
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
            
            # Create new forest
            $securePassword = ConvertTo-SecureString "Password123!" -AsPlainText -Force
            
            Install-ADDSForest `
                -CreateDnsDelegation:$false `
                -DatabasePath "C:\Windows\NTDS" `
                -DomainMode "WinThreshold" `
                -DomainName $DomainName `
                -DomainNetbiosName $NetbiosName `
                -ForestMode "WinThreshold" `
                -InstallDns:$true `
                -LogPath "C:\Windows\NTDS" `
                -NoRebootOnCompletion:$true `
                -SysvolPath "C:\Windows\SYSVOL" `
                -Force:$true `
                -SafeModeAdministratorPassword $securePassword
            
            # Configure IP address
            $interface = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
            New-NetIPAddress -InterfaceIndex $interface.ifIndex -IPAddress $IpAddress -PrefixLength 24
            
            # Restart the server to complete the domain setup
            Restart-Computer -Force
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $DomainName, $NetbiosName, $IpAddress
        
        Write-Log "Forest creation initiated for $DomainName. The server will restart to complete the setup."
    }
    catch {
        Write-Log "Failed to create forest $DomainName: $_" -Error
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
Write-Log "Starting domain creation for CRTE extension..."

# Create credential object for GOAD admin
$securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)

# Define the domains to create
$domains = @(
    @{
        DomainName = "bastion.local"
        NetbiosName = "BASTION"
        IpAddress = "192.168.56.20"
    },
    @{
        DomainName = "production.local"
        NetbiosName = "PRODUCTION"
        IpAddress = "192.168.56.30"
    },
    @{
        DomainName = "db.local"
        NetbiosName = "DB"
        IpAddress = "192.168.56.40"
    },
    @{
        DomainName = "dbvendor.local"
        NetbiosName = "DBVENDOR"
        IpAddress = "192.168.56.50"
    },
    @{
        DomainName = "usvendor.local"
        NetbiosName = "USVENDOR"
        IpAddress = "192.168.56.60"
    }
)

# Create each domain
foreach ($domain in $domains) {
    New-CrteForest -DomainName $domain.DomainName -NetbiosName $domain.NetbiosName -IpAddress $domain.IpAddress -Credential $credential
    
    # Wait for the domain controller to restart and become available
    Write-Log "Waiting for $($domain.DomainName) to become available..."
    Start-Sleep -Seconds 300
}

Write-Log "Domain creation completed successfully"
