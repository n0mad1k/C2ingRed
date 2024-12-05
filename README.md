Here’s the updated README to reflect the latest changes:

---

# **C2ingRed: Automated C2 Server Deployment**

Welcome to **C2ingRed**, a project designed to automate the deployment of Command and Control (C2) servers on cloud platforms (Linode and AWS) using Ansible and Python. This project simplifies the setup and configuration of a secure, operational C2 server equipped with popular red team tools.

---

## **Features**

- **Multi-Provider Deployment**:
  - Supports both **Linode** and **AWS** for flexible server provisioning.
  - Automatically handles region selection, instance naming, and resource creation.

- **Automated Setup**:
  - Installs and configures essential red team tools.
  - Automatically generates unique SSH keys per instance.

- **Security-First Approach**:
  - Enforces SSH-only access by disabling root password login.
  - Uses randomized instance names and resources for obfuscation.

- **Error Recovery**:
  - Automatically cleans up resources if deployment fails.

- **Debugging Options**:
  - Includes a `--debug` mode for verbose logging during deployment.

---

## **Getting Started**

### **Clone the Repository**

Clone this repository to your local machine:
```bash
git clone https://github.com/n0m4d1k/C2ingRed.git
cd C2ingRed
```

---

### **Prerequisites**

#### **1. Install Dependencies**

This project uses a `requirements.txt` file for managing Python dependencies. Install them with:
```bash
pip install -r requirements.txt
```

Dependencies include:
- [`ansible`](https://github.com/ansible/ansible): Automation tool for provisioning and configuration.
- [`linode_api4`](https://github.com/linode/linode_api4-python): Python client for the Linode API (used only for Linode deployments).

#### **2. API Credentials**

- **Linode**: Generate a personal access token in your Linode account [here](https://cloud.linode.com/profile/tokens).
- **AWS**: Create an IAM user with programmatic access and retrieve the access key and secret.

#### **3. Optional: Virtual Environment**

Create and activate a virtual environment to isolate dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
```

---

### **Configuration**

Each provider has its own directory containing playbooks and a `vars.yaml` file for configuration:

#### **Linode Configuration**

Edit `Linode/vars.yaml`:
```yaml
linode_token: "your-linode-api-token"
region_choices:
  - us-east
  - us-west
  # Additional regions...
plan: "g6-standard-2"
image: "linode/kali"
```

#### **AWS Configuration**

Edit `AWS/vars.yaml`:
```yaml
aws_access_key: "your-aws-access-key"
aws_secret_key: "your-aws-secret-key"
aws_region_choices:
  - us-east-1
  - us-west-1
  # Additional regions...
instance_type: "t2.medium"
ami_id: "ami-061b17d332829ab1c"  # Replace with the desired AMI
```

---

## **Usage**

### **Run the Deployment Script**

The deployment script, `deploy.py`, automates the setup of a C2 server.

| Argument         | Description                                               | Default Value      |
|-------------------|-----------------------------------------------------------|--------------------|
| `--provider`     | Choose the provider: `linode` or `aws`.                   | `linode`          |
| `--vars-file`    | Path to the variables file for Ansible.                   | `Linode/vars.yaml` or `AWS/vars.yaml` |
| `--debug`        | Enable debug mode for verbose Ansible output (`-vvv`).    | Disabled          |

#### **Examples**

1. **Linode Deployment (Default)**:
   ```bash
   python3 deploy.py
   ```

2. **AWS Deployment**:
   ```bash
   python3 deploy.py --provider aws
   ```

3. **Verbose Debug Mode**:
   ```bash
   python3 deploy.py --debug
   ```

---

## **Installed Tools**

### **Via `apt`**:
- `nmap`, `netcat`, `tcpdump`, `hydra`, `john`, `hashcat`, `sqlmap`
- `gobuster`, `dirb`, `enum4linux`, `dnsenum`, `seclists`, `responder`, `crackmapexec`

### **Via `pipx`**:
- [`NetExec`](https://github.com/Pennyw0rth/NetExec)
- [`SprayingToolkit`](https://github.com/byt3bl33d3r/SprayingToolkit)

### **Via `pipx`**:
- [`Impacket`](https://github.com/SecureAuthCorp/impacket)

### **Manually Installed**:
- [`Kerbrute`](https://github.com/ropnop/kerbrute)
- [`SharpCollection`](https://github.com/Flangvik/SharpCollection)
- [`PEASS-ng`](https://github.com/carlospolop/PEASS-ng)
- [`MailSniper`](https://github.com/dafthack/MailSniper)
- [`Inveigh`](https://github.com/Kevin-Robertson/Inveigh)

### **C2 Frameworks**:
- [`Sliver`](https://github.com/BishopFox/sliver)
- [`Metasploit Framework`](https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb)

---

## **Security Features**

1. **SSH Key Management**:
   - A new SSH key is generated for each deployment and stored in `~/.ssh`.

2. **Strict Access Controls**:
   - Disables root password login immediately after deployment.

3. **Randomization**:
   - Randomized instance names, SSH keys, and security group names to minimize detection.

4. **Automatic Cleanup**:
   - Cleans up resources (e.g., instances, security groups) if deployment fails.

---

## **Debugging**

Enable debug mode during deployment to view detailed logs:
```bash
python3 deploy.py --debug
```
