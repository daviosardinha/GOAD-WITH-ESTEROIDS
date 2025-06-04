# CRTE Extension for GOAD - Main Installation Script
# This script orchestrates the installation of CRTE-specific extensions to a standard GOAD environment

# Script parameters
param(
    [Parameter(Mandatory=$false)]
    [string]$GoadDcIp = "192.168.56.10",
    
    [Parameter(Mandatory=$false)]
    [string]$GoadAdminUser = "Administrator",
    
    [Parameter(Mandatory=$false)]
    [string]$GoadAdminPassword = "Password123!",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipDomainCreation = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipUserCreation = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipVulnerabilitySetup = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipServiceSetup = $false
)

# Script variables
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile = "$ScriptPath\crte_extension_install.log"
$ErrorLogFile = "$ScriptPath\crte_extension_error.log"

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

# Function to check if GOAD is accessible
function Test-GoadConnection {
    Write-Log "Testing connection to GOAD DC at $GoadDcIp..."
    
    try {
        $ping = Test-Connection -ComputerName $GoadDcIp -Count 1 -Quiet
        if (-not $ping) {
            Write-Log "Cannot ping GOAD DC at $GoadDcIp. Please ensure the GOAD environment is running." -Error
            return $false
        }
        
        # Try to establish a PowerShell session to the GOAD DC
        $securePassword = ConvertTo-SecureString $GoadAdminPassword -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($GoadAdminUser, $securePassword)
        
        $session = New-PSSession -ComputerName $GoadDcIp -Credential $credential -ErrorAction Stop
        Remove-PSSession $session
        
        Write-Log "Successfully connected to GOAD DC at $GoadDcIp"
        return $true
    }
    catch {
        Write-Log "Failed to connect to GOAD DC: $_" -Error
        return $false
    }
}

# Function to install CRTE domains
function Install-CrteDomains {
    Write-Log "Starting domain creation and trust configuration..."
    
    try {
        # Execute domain creation script
        & "$ScriptPath\domains\create_domains.ps1" -GoadDcIp $GoadDcIp -GoadAdminUser $GoadAdminUser -GoadAdminPassword $GoadAdminPassword
        
        # Execute trust setup script
        & "$ScriptPath\domains\setup_trusts.ps1" -GoadDcIp $GoadDcIp -GoadAdminUser $GoadAdminUser -GoadAdminPassword $GoadAdminPassword
        
        Write-Log "Domain creation and trust configuration completed successfully"
    }
    catch {
        Write-Log "Failed to create domains and configure trusts: $_" -Error
        return $false
    }
    
    return $true
}

# Function to create CRTE users and groups
function Install-CrteUsers {
    Write-Log "Starting user and group creation..."
    
    try {
        # Execute user creation script
        & "$ScriptPath\users\create_users.ps1" -GoadDcIp $GoadDcIp -GoadAdminUser $GoadAdminUser -GoadAdminPassword $GoadAdminPassword
        
        Write-Log "User and group creation completed successfully"
    }
    catch {
        Write-Log "Failed to create users and groups: $_" -Error
        return $false
    }
    
    return $true
}

# Function to configure vulnerabilities
function Install-CrteVulnerabilities {
    Write-Log "Starting vulnerability configuration..."
    
    try {
        # Execute vulnerability setup scripts
        $vulnerabilityScripts = Get-ChildItem -Path "$ScriptPath\vulnerabilities" -Filter "*.ps1" -Recurse
        
        foreach ($script in $vulnerabilityScripts) {
            Write-Log "Executing vulnerability script: $($script.Name)"
            & $script.FullName -GoadDcIp $GoadDcIp -GoadAdminUser $GoadAdminUser -GoadAdminPassword $GoadAdminPassword
        }
        
        Write-Log "Vulnerability configuration completed successfully"
    }
    catch {
        Write-Log "Failed to configure vulnerabilities: $_" -Error
        return $false
    }
    
    return $true
}

# Function to configure services
function Install-CrteServices {
    Write-Log "Starting service configuration..."
    
    try {
        # Execute service setup scripts
        $serviceScripts = Get-ChildItem -Path "$ScriptPath\services" -Filter "*.ps1" -Recurse
        
        foreach ($script in $serviceScripts) {
            Write-Log "Executing service script: $($script.Name)"
            & $script.FullName -GoadDcIp $GoadDcIp -GoadAdminUser $GoadAdminUser -GoadAdminPassword $GoadAdminPassword
        }
        
        Write-Log "Service configuration completed successfully"
    }
    catch {
        Write-Log "Failed to configure services: $_" -Error
        return $false
    }
    
    return $true
}

# Main installation process
Write-Log "Starting CRTE Extension installation for GOAD..."

# Check if GOAD is accessible
if (-not (Test-GoadConnection)) {
    Write-Log "Cannot proceed with installation. Please ensure GOAD is running and accessible." -Error
    exit 1
}

# Create domains and configure trusts
if (-not $SkipDomainCreation) {
    if (-not (Install-CrteDomains)) {
        Write-Log "Domain creation failed. Use -SkipDomainCreation to skip this step on retry." -Error
        exit 1
    }
} else {
    Write-Log "Skipping domain creation as requested"
}

# Create users and groups
if (-not $SkipUserCreation) {
    if (-not (Install-CrteUsers)) {
        Write-Log "User creation failed. Use -SkipUserCreation to skip this step on retry." -Error
        exit 1
    }
} else {
    Write-Log "Skipping user creation as requested"
}

# Configure vulnerabilities
if (-not $SkipVulnerabilitySetup) {
    if (-not (Install-CrteVulnerabilities)) {
        Write-Log "Vulnerability configuration failed. Use -SkipVulnerabilitySetup to skip this step on retry." -Error
        exit 1
    }
} else {
    Write-Log "Skipping vulnerability configuration as requested"
}

# Configure services
if (-not $SkipServiceSetup) {
    if (-not (Install-CrteServices)) {
        Write-Log "Service configuration failed. Use -SkipServiceSetup to skip this step on retry." -Error
        exit 1
    }
} else {
    Write-Log "Skipping service configuration as requested"
}

Write-Log "CRTE Extension installation completed successfully!"
Write-Log "Please refer to the documentation in the 'docs' folder for information on the available attack paths."
