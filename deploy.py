#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import time
import yaml
import json
import random
import string
import shutil
from datetime import datetime

# Constants
PROVIDERS = ["aws", "linode", "flokinet"]
DEFAULT_REGION = {
    "aws": "us-east-1",
    "linode": "us-east",
    "flokinet": "anonymous"
}
DEFAULT_SIZE = {
    "aws": "t2.micro",
    "linode": "g6-standard-1",
    "flokinet": "standard"
}

def setup_argparse():
    """Set up and return the argument parser"""
    parser = argparse.ArgumentParser(description='Deploy Red Team infrastructure')
    
    # Provider selection
    parser.add_argument('-p', '--provider', choices=PROVIDERS, help='Provider to use for deployment')
    
    # AWS-specific arguments
    parser.add_argument('--aws-key', help='AWS access key')
    parser.add_argument('--aws-secret', help='AWS secret key')
    parser.add_argument('--aws-region', help=f'AWS region (default: {DEFAULT_REGION["aws"]})')
    
    # Linode-specific arguments
    parser.add_argument('--linode-token', help='Linode API token')
    parser.add_argument('--linode-region', help=f'Linode region (default: {DEFAULT_REGION["linode"]})')
    
    # FlokiNET-specific arguments
    parser.add_argument('--flokinet', action='store_true', help='Use FlokiNET as the provider (manual setup required)')
    parser.add_argument('--flokinet-redirector-ip', help='FlokiNET redirector IP address')
    parser.add_argument('--flokinet-c2-ip', help='FlokiNET C2 server IP address')
    
    # General arguments
    parser.add_argument('--ssh-key', help='Path to SSH private key')
    parser.add_argument('--ssh-user', default='root', help='SSH username (default: root)')
    parser.add_argument('--size', help='Size/type of the instances')
    parser.add_argument('--region', help='Region for the instances')
    parser.add_argument('--redirector-name', default='redirector', help='Name for the redirector instance')
    parser.add_argument('--c2-name', default='c2', help='Name for the C2 instance')
    parser.add_argument('--teardown', action='store_true', help='Tear down existing infrastructure')
    
    return parser.parse_args()

def load_config(args):
    """Load configuration from a config file or environment variables"""
    config = {}
    
    # Check for config file
    if os.path.exists('config.yml'):
        with open('config.yml', 'r') as f:
            config = yaml.safe_load(f)
    
    # Override config with args
    provider = args.provider or config.get('provider')
    
    if provider == 'aws':
        config['aws_key'] = args.aws_key or config.get('aws_key') or os.environ.get('AWS_ACCESS_KEY_ID')
        config['aws_secret'] = args.aws_secret or config.get('aws_secret') or os.environ.get('AWS_SECRET_ACCESS_KEY')
        config['aws_region'] = args.aws_region or config.get('aws_region') or DEFAULT_REGION['aws']
    elif provider == 'linode':
        config['linode_token'] = args.linode_token or config.get('linode_token') or os.environ.get('LINODE_TOKEN')
        config['linode_region'] = args.linode_region or config.get('linode_region') or DEFAULT_REGION['linode']
    elif provider == 'flokinet' or args.flokinet:
        provider = 'flokinet'
        config['flokinet_redirector_ip'] = args.flokinet_redirector_ip or config.get('flokinet_redirector_ip')
        config['flokinet_c2_ip'] = args.flokinet_c2_ip or config.get('flokinet_c2_ip')
    
    config['provider'] = provider
    config['ssh_key'] = args.ssh_key or config.get('ssh_key')
    config['ssh_user'] = args.ssh_user or config.get('ssh_user') or 'root'
    config['size'] = args.size or config.get('size') or DEFAULT_SIZE.get(provider, 'small')
    config['region'] = args.region or config.get('region') or DEFAULT_REGION.get(provider, 'us-east')
    config['redirector_name'] = args.redirector_name or config.get('redirector_name') or 'redirector'
    config['c2_name'] = args.c2_name or config.get('c2_name') or 'c2'
    config['teardown'] = args.teardown
    
    return config

def validate_config(config):
    """Validate the configuration"""
    if not config.get('provider'):
        print("[-] Error: Provider must be specified")
        return False
    
    if config['provider'] == 'aws':
        if not config.get('aws_key') or not config.get('aws_secret'):
            print("[-] Error: AWS credentials must be provided")
            return False
    
    if config['provider'] == 'linode':
        if not config.get('linode_token'):
            print("[-] Error: Linode token must be provided")
            return False
    
    if config['provider'] == 'flokinet':
        if not config.get('flokinet_redirector_ip') or not config.get('flokinet_c2_ip'):
            print("[-] Error: FlokiNET server IPs must be provided")
            print("    Use --flokinet-redirector-ip and --flokinet-c2-ip")
            return False
    
    if not config.get('ssh_key') and config['provider'] != 'flokinet':
        print("[-] Error: SSH key must be provided")
        return False
    
    return True

def deploy_aws(config):
    """Deploy infrastructure using AWS provider"""
    print("[+] Deploying AWS infrastructure...")
    
    # Set AWS environment variables
    os.environ['AWS_ACCESS_KEY_ID'] = config['aws_key']
    os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret']
    
    # Create a temporary inventory file for Ansible
    with open('inventory_aws.yml', 'w') as f:
        f.write("---\n")
        f.write("all:\n")
        f.write("  vars:\n")
        f.write(f"    ansible_ssh_private_key_file: {config['ssh_key']}\n")
        f.write(f"    ansible_user: {config['ssh_user']}\n")
        f.write(f"    ansible_python_interpreter: /usr/bin/python3\n")
        f.write("  children:\n")
        f.write("    redirectors:\n")
        f.write("      hosts:\n")
        f.write("        redirector:\n")
        f.write("          ansible_host: '{{ redirector_ip }}'\n")
        f.write("    c2servers:\n")
        f.write("      hosts:\n")
        f.write("        c2:\n")
        f.write("          ansible_host: '{{ c2_ip }}'\n")
    
    # Run AWS provisioning playbook
    try:
        extra_vars = {
            'region': config['aws_region'],
            'size': config['size'],
            'redirector_name': config['redirector_name'],
            'c2_name': config['c2_name'],
            'teardown': config['teardown']
        }
        
        extra_vars_str = ' '.join([f"{k}={v}" for k, v in extra_vars.items()])
        cmd = f"ansible-playbook -i inventory_aws.yml AWS/provision.yml -e '{extra_vars_str}'"
        
        print(f"[+] Running: {cmd}")
        subprocess.run(cmd, shell=True, check=True)
        
        print("[+] AWS infrastructure deployed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("[-] Error: Failed to deploy AWS infrastructure")
        return False
    finally:
        # Clean up temporary inventory file
        if os.path.exists('inventory_aws.yml'):
            os.remove('inventory_aws.yml')

def deploy_linode(config):
    """Deploy infrastructure using Linode provider"""
    print("[+] Deploying Linode infrastructure...")
    
    # Set Linode environment variables
    os.environ['LINODE_TOKEN'] = config['linode_token']
    
    # Create a temporary inventory file for Ansible
    with open('inventory_linode.yml', 'w') as f:
        f.write("---\n")
        f.write("all:\n")
        f.write("  vars:\n")
        f.write(f"    ansible_ssh_private_key_file: {config['ssh_key']}\n")
        f.write(f"    ansible_user: {config['ssh_user']}\n")
        f.write(f"    ansible_python_interpreter: /usr/bin/python3\n")
        f.write("  children:\n")
        f.write("    redirectors:\n")
        f.write("      hosts:\n")
        f.write("        redirector:\n")
        f.write("          ansible_host: '{{ redirector_ip }}'\n")
        f.write("    c2servers:\n")
        f.write("      hosts:\n")
        f.write("        c2:\n")
        f.write("          ansible_host: '{{ c2_ip }}'\n")
    
    # Run Linode provisioning playbook
    try:
        extra_vars = {
            'region': config['linode_region'],
            'size': config['size'],
            'redirector_name': config['redirector_name'],
            'c2_name': config['c2_name'],
            'teardown': config['teardown']
        }
        
        extra_vars_str = ' '.join([f"{k}={v}" for k, v in extra_vars.items()])
        cmd = f"ansible-playbook -i inventory_linode.yml Linode/provision.yml -e '{extra_vars_str}'"
        
        print(f"[+] Running: {cmd}")
        subprocess.run(cmd, shell=True, check=True)
        
        print("[+] Linode infrastructure deployed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("[-] Error: Failed to deploy Linode infrastructure")
        return False
    finally:
        # Clean up temporary inventory file
        if os.path.exists('inventory_linode.yml'):
            os.remove('inventory_linode.yml')

def deploy_flokinet(config):
    """Deploy infrastructure using FlokiNET provider"""
    print("[+] Deploying FlokiNET infrastructure...")
    
    # Create a temporary inventory file for Ansible
    with open('inventory_flokinet.yml', 'w') as f:
        f.write("---\n")
        f.write("all:\n")
        f.write("  children:\n")
        f.write("    redirectors:\n")
        f.write("      hosts:\n")
        f.write("        redirector:\n")
        f.write(f"          ansible_host: {config['flokinet_redirector_ip']}\n")
        f.write(f"          ansible_user: {config['ssh_user']}\n")
        if config.get('ssh_key'):
            f.write(f"          ansible_ssh_private_key_file: {config['ssh_key']}\n")
        f.write("          ansible_python_interpreter: /usr/bin/python3\n")
        f.write("    c2servers:\n")
        f.write("      hosts:\n")
        f.write("        c2:\n")
        f.write(f"          ansible_host: {config['flokinet_c2_ip']}\n")
        f.write(f"          ansible_user: {config['ssh_user']}\n")
        if config.get('ssh_key'):
            f.write(f"          ansible_ssh_private_key_file: {config['ssh_key']}\n")
        f.write("          ansible_python_interpreter: /usr/bin/python3\n")
    
    # Run FlokiNET provisioning playbook
    try:
        cmd = ["ansible-playbook", "-i", "inventory_flokinet.yml", "FlokiNET/provision.yml"]
        print(f"[+] Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print("[+] FlokiNET infrastructure deployed successfully!")
        return True
    except subprocess.CalledProcessError:
        print("[-] Error: Failed to deploy FlokiNET infrastructure")
        return False
    finally:
        # Clean up temporary inventory file
        if os.path.exists('inventory_flokinet.yml'):
            os.remove('inventory_flokinet.yml')

def generate_ssh_key():
    """Generate a new SSH key if one is not provided"""
    key_path = os.path.expanduser("~/.ssh/c2ingred_key")
    
    if os.path.exists(key_path):
        print(f"[+] Using existing SSH key: {key_path}")
        return key_path
    
    print(f"[+] Generating new SSH key: {key_path}")
    try:
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""], check=True)
        return key_path
    except subprocess.CalledProcessError:
        print("[-] Error: Failed to generate SSH key")
        return None

def interactive_config():
    """Interactively collect configuration"""
    config = {}
    
    # Select provider
    print("\n=== Provider Selection ===")
    print("Available providers:")
    for i, provider in enumerate(PROVIDERS):
        print(f"  {i+1}. {provider}")
    
    while True:
        try:
            choice = int(input("\nSelect provider (1-3): ")) - 1
            if 0 <= choice < len(PROVIDERS):
                config['provider'] = PROVIDERS[choice]
                break
            else:
                print("Invalid choice. Please enter a number between 1 and 3.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    # Provider-specific configuration
    if config['provider'] == 'aws':
        print("\n=== AWS Configuration ===")
        config['aws_key'] = input("AWS Access Key: ")
        config['aws_secret'] = input("AWS Secret Key: ")
        config['aws_region'] = input(f"AWS Region (default: {DEFAULT_REGION['aws']}): ") or DEFAULT_REGION['aws']
    
    elif config['provider'] == 'linode':
        print("\n=== Linode Configuration ===")
        config['linode_token'] = input("Linode API Token: ")
        config['linode_region'] = input(f"Linode Region (default: {DEFAULT_REGION['linode']}): ") or DEFAULT_REGION['linode']
    
    elif config['provider'] == 'flokinet':
        print("\n=== FlokiNET Configuration ===")
        print("Note: FlokiNET requires manual server setup due to their privacy focus")
        config['flokinet_redirector_ip'] = input("FlokiNET Redirector IP: ")
        config['flokinet_c2_ip'] = input("FlokiNET C2 Server IP: ")
    
    # General configuration
    print("\n=== General Configuration ===")
    config['ssh_user'] = input(f"SSH Username (default: root): ") or 'root'
    
    # SSH key
    ssh_key = input("Path to SSH private key (leave empty to generate): ")
    if not ssh_key:
        ssh_key = generate_ssh_key()
    config['ssh_key'] = ssh_key
    
    # Size and region
    if config['provider'] != 'flokinet':
        config['size'] = input(f"Instance size (default: {DEFAULT_SIZE[config['provider']]}): ") or DEFAULT_SIZE[config['provider']]
        config['region'] = input(f"Region (default: {DEFAULT_REGION[config['provider']]}): ") or DEFAULT_REGION[config['provider']]
    
    # Instance names
    config['redirector_name'] = input("Redirector name (default: redirector): ") or 'redirector'
    config['c2_name'] = input("C2 server name (default: c2): ") or 'c2'
    
    return config

def save_config(config):
    """Save configuration to config.yml file"""
    # Remove sensitive data before saving
    config_to_save = config.copy()
    if 'aws_key' in config_to_save:
        config_to_save['aws_key'] = '***'
    if 'aws_secret' in config_to_save:
        config_to_save['aws_secret'] = '***'
    if 'linode_token' in config_to_save:
        config_to_save['linode_token'] = '***'
    
    with open('config.yml', 'w') as f:
        yaml.dump(config_to_save, f, default_flow_style=False)
    
    print(f"[+] Configuration saved to config.yml")

def main():
    """Main function"""
    print("========================================")
    print("C2ingRed - Red Team Infrastructure Setup")
    print("========================================")
    
    args = setup_argparse()
    
    # Interactive mode if no arguments provided
    if len(sys.argv) == 1:
        config = interactive_config()
    else:
        config = load_config(args)
    
    # Validate configuration
    if not validate_config(config):
        return
    
    # Save configuration
    save_config(config)
    
    # Deploy infrastructure based on provider
    if config['provider'] == 'aws':
        success = deploy_aws(config)
    elif config['provider'] == 'linode':
        success = deploy_linode(config)
    elif config['provider'] == 'flokinet':
        success = deploy_flokinet(config)
    else:
        print(f"[-] Error: Unsupported provider: {config['provider']}")
        return
    
    if success:
        print("\n[+] Deployment completed successfully!")
        if config['provider'] != 'flokinet':
            print("\n[+] Your infrastructure is now ready to use!")
            print(f"[+] Redirector: {config['redirector_name']}")
            print(f"[+] C2 Server: {config['c2_name']}")
        else:
            print("\n[+] Your FlokiNET infrastructure is now configured with:")
            print(f"[+] Zero-logs configuration")
            print(f"[+] Automated shell handler")
            print(f"[+] Sliver C2 framework")
            print(f"[+] Anti-forensics capabilities")
            print("\n[+] To use the automated shell handler, configure your Rubber Ducky with:")
            print(f"[+] Redirector IP: {config['flokinet_redirector_ip']}")
    else:
        print("\n[-] Deployment failed.")

if __name__ == "__main__":
    main()