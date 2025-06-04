# CRTE Extension for GOAD - Installation Guide

This guide provides step-by-step instructions for installing and configuring the CRTE (Certified Red Team Expert) extension on top of a standard GOAD (Game of Active Directory) deployment.

## Prerequisites

Before installing the CRTE extension, ensure you have:

1. A working GOAD installation (Full variant recommended)
2. PowerShell 5.1 or higher on your host machine
3. Administrative access to the GOAD environment
4. At least 16GB RAM and 50GB free disk space for the complete environment

## Installation Steps

### 1. Deploy Standard GOAD

First, deploy a standard GOAD environment following the official documentation:

```bash
# Clone the GOAD repository
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD

# Deploy GOAD using the provided script
./goad.sh
```

Verify that your GOAD deployment is working correctly before proceeding.

### 2. Install CRTE Extension

Once GOAD is deployed and working, you can install the CRTE extension:

```powershell
# Extract the CRTE-Extension package
Expand-Archive -Path CRTE-Extension.zip -DestinationPath C:\CRTE-Extension

# Navigate to the extension directory
cd C:\CRTE-Extension

# Run the installation script with default settings
.\install.ps1
```

The installation script will:
1. Connect to your GOAD domain controller
2. Create additional forests and domains
3. Configure trust relationships
4. Create users and groups
5. Configure vulnerabilities for CRTE attack scenarios

### 3. Customizing the Installation

You can customize the installation by providing parameters to the installation script:

```powershell
# Customize the installation
.\install.ps1 -GoadDcIp "192.168.56.10" -GoadAdminUser "Administrator" -GoadAdminPassword "Password123!"
```

To skip specific parts of the installation:

```powershell
# Skip domain creation if you've already created the domains
.\install.ps1 -SkipDomainCreation

# Skip user creation
.\install.ps1 -SkipUserCreation

# Skip vulnerability setup
.\install.ps1 -SkipVulnerabilitySetup
```

## Troubleshooting

### Common Issues

#### Connection Issues

If the installation script cannot connect to your GOAD domain controller:

1. Verify that the GOAD VMs are running
2. Check that you're using the correct IP address for the domain controller
3. Ensure the administrator credentials are correct
4. Check that WinRM is properly configured on the domain controller

#### Domain Creation Failures

If domain creation fails:

1. Check the error logs in the `crte_extension_error.log` file
2. Ensure the domain controllers have sufficient resources
3. Try running the domain creation script separately:
   ```powershell
   .\domains\create_domains.ps1 -GoadDcIp "192.168.56.10" -GoadAdminUser "Administrator" -GoadAdminPassword "Password123!"
   ```

#### Trust Configuration Issues

If trust configuration fails:

1. Ensure DNS is properly configured between domains
2. Check that the domain controllers can resolve each other's names
3. Try running the trust setup script separately:
   ```powershell
   .\domains\setup_trusts.ps1 -GoadDcIp "192.168.56.10" -GoadAdminUser "Administrator" -GoadAdminPassword "Password123!"
   ```

## Validation

After installation, you should validate that the CRTE extension is properly configured:

1. Verify that all domains are created and accessible
2. Check that trust relationships are established
3. Confirm that users and groups are created
4. Test the attack paths as described in the attack path documentation

You can use the validation script to automatically check the configuration:

```powershell
.\validate.ps1
```

## Next Steps

Once the CRTE extension is installed and validated, you can:

1. Explore the attack paths documented in `docs/attack_paths.md`
2. Practice the CRTE attack scenarios
3. Use the student machine to connect to the environment and start your attacks

For detailed information on the available attack paths and scenarios, refer to the attack path documentation.
