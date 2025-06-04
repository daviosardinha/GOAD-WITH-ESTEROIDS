# CRTE Extension for GOAD

This extension package adds CRTE (Certified Red Team Expert) specific domains, trusts, and attack paths to a standard GOAD (Game of Active Directory) installation.

## Overview

Instead of replacing the entire GOAD infrastructure, this extension package provides scripts and configurations that can be applied to an existing GOAD deployment. This modular approach ensures compatibility with your virtualization environment while adding all the necessary components for CRTE exam preparation.

## Prerequisites

- A working GOAD installation (Full variant recommended)
- PowerShell 5.1 or higher on the host machine
- Administrative access to the GOAD environment

## Directory Structure

```
CRTE-Extension/
├── README.md                     # This file
├── install.ps1                   # Main installation script
├── domains/                      # Domain creation scripts
│   ├── create_domains.ps1        # Creates additional forests and domains
│   ├── setup_trusts.ps1          # Configures trust relationships
│   └── domain_config/            # Domain configuration files
├── users/                        # User and group creation scripts
│   ├── create_users.ps1          # Creates users across domains
│   └── user_config/              # User configuration files
├── vulnerabilities/              # Vulnerability implementation scripts
│   ├── kerberos/                 # Kerberos-related vulnerabilities
│   ├── delegation/               # Delegation misconfigurations
│   ├── acl/                      # ACL misconfigurations
│   ├── trusts/                   # Trust relationship vulnerabilities
│   └── other/                    # Other CRTE-specific vulnerabilities
├── services/                     # Service configuration scripts
│   ├── exchange/                 # Exchange server configuration
│   ├── sql/                      # SQL server configuration
│   └── azure_ad/                 # Azure AD Connect configuration
└── docs/                         # Documentation
    ├── installation.md           # Installation guide
    ├── attack_paths.md           # Attack path documentation
    └── validation.md             # Validation procedures
```

## Installation

1. Deploy a standard GOAD environment using the official GOAD repository
2. Verify that the GOAD environment is working correctly
3. Copy this extension package to your host machine
4. Run the main installation script: `.\install.ps1`
5. Follow the on-screen instructions to complete the installation

For detailed installation instructions, see [docs/installation.md](docs/installation.md).

## Features

This extension adds the following features to a standard GOAD environment:

### Additional Forests and Domains

- Bastion.local forest
- Production.local forest
- DB.local forest
- DBvendor.local forest
- USvendor.local forest

### Trust Relationships

- One-way trust from kingandqueen.local (GOAD) to bastion.local
- One-way trust from bastion.local to production.local
- Selective authentication trust from north.kingandqueen.local to db.local
- Two-way trust between db.local and dbvendor.local
- One-way trust from north.kingandqueen.local to usvendor.local

### Attack Scenarios

- Local privilege escalation paths
- Kerberos delegation misconfigurations
- Resource-Based Constrained Delegation (RBCD)
- Shadow Credentials
- ACL misconfigurations
- Trust relationship vulnerabilities
- Azure AD Connect credential extraction
- MSSQL server link abuse
- Exchange server vulnerabilities

## Documentation

- [Installation Guide](docs/installation.md)
- [Attack Paths](docs/attack_paths.md)
- [Validation Procedures](docs/validation.md)

## Mapping to GOAD

This extension maps CRTE requirements to the GOAD environment as follows:

- kingandqueen.local → techcorp.local
- north.kingandqueen.local → us.techcorp.local
- south.kingandqueen.local → (not used in CRTE)

Additional forests and domains are created as needed for CRTE scenarios.

## Credits

This extension is based on the [GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD) project by Orange Cyberdefense.
