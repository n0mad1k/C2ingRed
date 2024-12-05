# **C2ingRed: Automated C2 Server Deployment**

Welcome to **C2ingRed**, a project designed to automate the deployment of a Command and Control (C2) server on Linode instances using Ansible and Python. This project simplifies the setup and configuration of a secure, operational C2 server equipped with popular red team tools.

---

## **Features**

- **Automated Deployment**:
  - Provisions Linode instances with randomized regions and instance names to minimize IOCs.
  - Automatically generates and configures secure SSH keys.

- **Red Team Tool Installation**:
  - Prepares the server with essential tools like `Sliver`, `Metasploit`, `SharpCollection`, `PEASS-ng`, and others.

- **Security First**:
  - Disables root password login immediately after deployment.
  - SSH-based authentication for all access.

- **Debugging Options**:
  - Includes a `--debug` mode to enable detailed logging for troubleshooting.

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
- [`linode_api4`](https://github.com/linode/linode_api4-python): Python client for the Linode API.

#### **2. Linode API Token**

Generate a personal access token in your Linode account [here](https://cloud.linode.com/profile/tokens) and save it for use in the `c2-vars.yaml` file.

#### **3. Optional: Virtual Environment**

Create and activate a virtual environment to isolate dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
```

---

### **Configuration**

1. Open the `c2-vars.yaml` file in a text editor.
2. Add your Linode API token and customize other variables as needed:
   ```yaml
   linode_token: "your-linode-api-token"
   region_choices:
     - ap-west
     - ca-central
     - ap-southeast
     - us-iad
     - us-ord
     - fr-par
     - us-sea
     - br-gru
     - nl-ams
     - se-sto
     - es-mad
     - in-maa
     - jp-osa
     - it-mil
     - us-mia
     - id-cgk
     - us-lax
     - gb-lon
     - au-mel
     - in-bom-2
     - de-fra-2
     - sg-sin-2
     - us-central
     - us-west
     - us-southeast
     - us-east
     - eu-west
     - ap-south
     - eu-central
     - ap-northeast
   plan: "g6-standard-2"
   image: "linode/kali""
   ```

---

## **Usage**

### **Run the Deployment Script**

The deployment script, `deploy.py`, automates the setup of a Linode instance and installs the necessary tools.

| Argument         | Description                                               | Default Value      |
|-------------------|-----------------------------------------------------------|--------------------|
| `--vars-file`    | Path to the variables file for Ansible.                   | `c2-vars.yaml`    |
| `--playbook`     | Path to the Ansible playbook file.                        | `c2-deploy.yaml`  |
| `--debug`        | Enable debug mode for verbose Ansible output (`-vvv`).    | Disabled          |

#### **Examples**

1. **Standard Deployment**:
   ```bash
   python3 deploy.py
   ```

2. **Verbose Debug Mode**:
   ```bash
   python3 deploy.py --debug
   ```

3. **Custom Variables and Playbook**:
   ```bash
   python3 deploy.py --vars-file custom-vars.yaml --playbook custom-playbook.yaml
   ```

---

## **Installed Tools**

### **Via `apt`**:
- `nmap`, `netcat`, `tcpdump`, `hydra`, `john`, `hashcat`, `sqlmap`
- `gobuster`, `dirb`, `enum4linux`, `dnsenum`, `seclists`, `responder`

### **Via `pipx`**:
- [`NetExec`](https://github.com/Pennyw0rth/NetExec)
- [`SprayingToolkit`](https://github.com/byt3bl33d3r/SprayingToolkit)

### **Via `pip`**:
- [`Impacket`](https://github.com/SecureAuthCorp/impacket)
- [`CrackMapExec`](https://github.com/byt3bl33d3r/CrackMapExec)

### **Manually Installed**:
- [`Kerbrute`](https://github.com/ropnop/kerbrute)
- [`SharpCollection`](https://github.com/Flangvik/SharpCollection)
- [`PEASS-ng`](https://github.com/carlospolop/PEASS-ng)
- [`MailSniper`](https://github.com/dafthack/MailSniper)
- [`Inveigh`](https://github.com/Kevin-Robertson/Inveigh)

### **C2 Frameworks**:
- [`Sliver`](https://github.com/BishopFox/sliver)
- [`Metasploit Framework`](https://github.com/rapid7/metasploit-framework)

---

## **Security Features**

1. **SSH Key Management**:
   - A new SSH key is generated for each deployment and stored in `~/.ssh`.

2. **Strict Access Controls**:
   - Disables root password login immediately after deployment.

3. **Randomization**:
   - Randomized instance names and regions to minimize detection.

---

## **Debugging**

Enable debug mode during deployment to view detailed logs:
```bash
python3 deploy.py --debug
```