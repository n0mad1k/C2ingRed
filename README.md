# **C2ingRed: Automated C2 Server Deployment**

Welcome to **C2ingRed**, a project designed to automate the deployment of Command and Control (C2) servers on cloud platforms (Linode and AWS) using Ansible and Python. This project simplifies the setup and configuration of a secure, operational C2 server equipped with popular red team tools.

---

## **Features**

### **Multi-Provider Support**
- **AWS** and **Linode** cloud platforms are supported.
- Automates resource provisioning, configuration, and cleanup.

### **Automated Server Configuration**
- Installs and configures a complete C2 stack with essential red team tools.
- Dynamically handles instance setup, including SSH keys, security groups, and domain configurations.

### **Security Focus**
- Implements strict SSH access policies and obfuscation techniques to enhance operational security.
- Automatic cleanup of resources on deployment failure.

### **Error Recovery and Debugging**
- Detailed error recovery and cleanup for failed deployments.
- Debugging mode for verbose logging and troubleshooting.

---

## **Installed Tools**

### **APT Tools**
- Common utilities (`git`, `wget`, `curl`, etc.)
- Pentesting tools: `nmap`, `tcpdump`, `hydra`, `john`, `hashcat`, `sqlmap`, `gobuster`, `responder`, `crackmapexec`, `dnsenum`, and more.

### **Custom Tools**
- **Python tools via pipx**:
  - [`NetExec`](https://github.com/Pennyw0rth/NetExec)
  - [`SprayingToolkit`](https://github.com/blacklanternsecurity/TREVORspray)
  - [`Impacket`](https://github.com/SecureAuthCorp/impacket)
- **Manual Installations**:
  - [`Kerbrute`](https://github.com/ropnop/kerbrute)
  - [`SharpCollection`](https://github.com/Flangvik/SharpCollection)
  - [`PEASS-ng`](https://github.com/carlospolop/PEASS-ng)
  - [`MailSniper`](https://github.com/dafthack/MailSniper)
  - [`Inveigh`](https://github.com/Kevin-Robertson/Inveigh)
  - ['GoPhish'](https://github.com/gophish/gophish)
- **C2 Frameworks**:
  - [`Sliver`](https://github.com/BishopFox/sliver)
  - [`Metasploit`](https://github.com/rapid7/metasploit-framework)

---

Here’s the updated README section with all the parameters and updated usage instructions to include the mandatory `--aws-access-key` and `--aws-secret-key` arguments for AWS deployments:

---

## **Usage**

### **Setup and Prerequisites**
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Configure provider-specific variables in `vars.yaml` files:
   - **AWS**: `AWS/vars.yaml`
   - **Linode**: `Linode/vars.yaml`

3. (Optional) Use a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

### **Run the Deployment Script**
Deploy your C2 server by specifying the provider and required parameters:

```bash
python3 deploy.py --provider aws --aws-access-key <your_access_key> --aws-secret-key <your_secret_key> --debug --region us-east-1
```

| Argument            | Description                                                       | Required        | Default Value   |
|----------------------|-------------------------------------------------------------------|-----------------|-----------------|
| `--provider`        | Choose between `aws` or `linode`.                                 | Yes             | `linode`        |
| `--region`          | Specify deployment region. If not provided, a random region is chosen. | No              | Random region   |
| `--debug`           | Enable verbose output for debugging.                              | No              | Disabled        |
| `--ssh`             | SSH into the deployed instance after deployment.                 | No              | Disabled        |
| `--aws-access-key`  | AWS Access Key for authentication (required for AWS provider).    | Yes (AWS only)  | None            |
| `--aws-secret-key`  | AWS Secret Key for authentication (required for AWS provider).    | Yes (AWS only)  | None            |
| `--aws-session-token` | Optional AWS session token for temporary credentials.          | No              | None            |