# CRTE Extension for GOAD - SQL Server Link Vulnerabilities
# This script configures SQL Server link vulnerabilities for CRTE attack scenarios

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
$LogFile = "$ScriptPath\sql_link_vulnerabilities.log"

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

# Function to configure SQL Server linked server
function Set-SQLLinkedServer {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SQLServerIP,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory=$true)]
        [string]$LinkedServerName,
        
        [Parameter(Mandatory=$true)]
        [string]$LinkedServerIP,
        
        [Parameter(Mandatory=$true)]
        [string]$RemoteUser,
        
        [Parameter(Mandatory=$true)]
        [string]$RemotePassword
    )
    
    Write-Log "Configuring SQL Server linked server $LinkedServerName on $SQLServerIP"
    
    # Create a PowerShell session to the SQL Server
    $session = New-PSSession -ComputerName $SQLServerIP -Credential $Credential
    
    try {
        # Create a script block to configure the linked server
        $scriptBlock = {
            param($LinkedServerName, $LinkedServerIP, $RemoteUser, $RemotePassword)
            
            # Install SQL Server PowerShell module if not already installed
            if (-not (Get-Module -ListAvailable -Name SqlServer)) {
                Install-Module -Name SqlServer -Force -AllowClobber
            }
            
            # Import the SQL Server module
            Import-Module SqlServer
            
            # Create the linked server
            $query = @"
EXEC master.dbo.sp_addlinkedserver 
    @server = N'$LinkedServerName', 
    @srvproduct=N'SQL Server', 
    @provider=N'SQLNCLI', 
    @datasrc=N'$LinkedServerIP'

EXEC master.dbo.sp_addlinkedsrvlogin 
    @rmtsrvname=N'$LinkedServerName',
    @useself=N'False',
    @locallogin=NULL,
    @rmtuser=N'$RemoteUser',
    @rmtpassword=N'$RemotePassword'

EXEC master.dbo.sp_serveroption 
    @server=N'$LinkedServerName', 
    @optname=N'rpc out', 
    @optvalue=N'true'
"@
            
            # Execute the query
            Invoke-Sqlcmd -Query $query -ServerInstance "localhost"
            
            # Verify the linked server was created
            $verifyQuery = "SELECT name FROM sys.servers WHERE is_linked = 1 AND name = '$LinkedServerName'"
            $result = Invoke-Sqlcmd -Query $verifyQuery -ServerInstance "localhost"
            
            if ($result) {
                Write-Output "Successfully configured linked server $LinkedServerName"
            } else {
                Write-Output "Failed to configure linked server $LinkedServerName"
            }
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $LinkedServerName, $LinkedServerIP, $RemoteUser, $RemotePassword
        
        Write-Log "SQL Server linked server $LinkedServerName configured on $SQLServerIP"
    }
    catch {
        Write-Log "Failed to configure SQL Server linked server: $_" -Error
        throw
    }
    finally {
        # Close the PowerShell session
        if ($session) {
            Remove-PSSession $session
        }
    }
}

# Function to enable xp_cmdshell on SQL Server
function Enable-XpCmdShell {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SQLServerIP,
        
        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential
    )
    
    Write-Log "Enabling xp_cmdshell on SQL Server $SQLServerIP"
    
    # Create a PowerShell session to the SQL Server
    $session = New-PSSession -ComputerName $SQLServerIP -Credential $Credential
    
    try {
        # Create a script block to enable xp_cmdshell
        $scriptBlock = {
            # Install SQL Server PowerShell module if not already installed
            if (-not (Get-Module -ListAvailable -Name SqlServer)) {
                Install-Module -Name SqlServer -Force -AllowClobber
            }
            
            # Import the SQL Server module
            Import-Module SqlServer
            
            # Enable xp_cmdshell
            $query = @"
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
"@
            
            # Execute the query
            Invoke-Sqlcmd -Query $query -ServerInstance "localhost"
            
            # Verify xp_cmdshell is enabled
            $verifyQuery = "SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell'"
            $result = Invoke-Sqlcmd -Query $verifyQuery -ServerInstance "localhost"
            
            if ($result.value -eq 1) {
                Write-Output "Successfully enabled xp_cmdshell on SQL Server"
            } else {
                Write-Output "Failed to enable xp_cmdshell on SQL Server"
            }
        }
        
        # Execute the script block on the remote server
        Invoke-Command -Session $session -ScriptBlock $scriptBlock
        
        Write-Log "xp_cmdshell enabled on SQL Server $SQLServerIP"
    }
    catch {
        Write-Log "Failed to enable xp_cmdshell: $_" -Error
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
Write-Log "Starting SQL Server link vulnerability configuration for CRTE extension..."

# Create credential object for GOAD admin
$securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)

# 1. Configure linked server from us-mssql (north.kingandqueen.local) to db-sqlprod (db.local)
# This simulates the SQL Server link from us.techcorp.local to db.local
Set-SQLLinkedServer -SQLServerIP "192.168.56.23" -Credential $credential -LinkedServerName "DB-SQLPROD" -LinkedServerIP "192.168.56.31" -RemoteUser "sa" -RemotePassword "SqlPassword123!"

# 2. Configure linked server from db-sqlprod (db.local) to db-sqlsrv (db.local)
# This simulates the SQL Server link within db.local
Set-SQLLinkedServer -SQLServerIP "192.168.56.31" -Credential $credential -LinkedServerName "DB-SQLSRV" -LinkedServerIP "192.168.56.32" -RemoteUser "sa" -RemotePassword "SqlPassword123!"

# 3. Enable xp_cmdshell on all SQL Servers
# This enables command execution through SQL Server
Enable-XpCmdShell -SQLServerIP "192.168.56.23" -Credential $credential  # us-mssql
Enable-XpCmdShell -SQLServerIP "192.168.56.31" -Credential $credential  # db-sqlprod
Enable-XpCmdShell -SQLServerIP "192.168.56.32" -Credential $credential  # db-sqlsrv

Write-Log "SQL Server link vulnerability configuration completed successfully"
