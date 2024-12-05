import os
import subprocess
import argparse
import random
import string
import json
import yaml

# Disable Ansible host key checking
os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"

def generate_random_string(length=12):
    """Generate a random string of letters and digits."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_ssh_key(key_name):
    """Generate an SSH key with the given key name."""
    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, exist_ok=True)

    private_key_path = os.path.join(ssh_dir, key_name)
    public_key_path = f"{private_key_path}.pub"

    print(f"Generating SSH key: {key_name}")
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", private_key_path, "-N", "", "-C", ""],
        check=True
    )

    os.chmod(private_key_path, 0o600)
    return private_key_path, public_key_path

def fetch_instance_ip(provider, instance_label):
    """Fetch the public IP address of the deployed instance."""
    print(f"Fetching instance IP for label: {instance_label} (Provider: {provider})")
    if provider == "aws":
        command = [
            "aws", "ec2", "describe-instances",
            "--filters", f"Name=tag:Name,Values={instance_label}",
            "--query", "Reservations[*].Instances[*].PublicIpAddress",
            "--output", "text"
        ]
    else:  # linode
        command = [
            "linode-cli", "linodes", "list",
            "--json"
        ]
    try:
        result = subprocess.run(command, capture_output=True, check=True, text=True)
        if provider == "aws":
            return result.stdout.strip()
        else:  # Parse Linode JSON output
            linodes = json.loads(result.stdout)
            for linode in linodes:
                if linode["label"] == instance_label:
                    return linode["ipv4"][0]  # Return the first public IPv4 address
    except Exception as e:
        print(f"Error fetching instance IP: {e}")
        raise ValueError("Could not determine instance IP. Ensure the instance exists and API credentials are correct.")

def ssh_into_instance(private_key_path, ip_address, username="root"):
    """SSH into the deployed instance."""
    print(f"Connecting to {username}@{ip_address}...")
    ssh_command = [
        "ssh",
        "-i", private_key_path,
        f"{username}@{ip_address}"
    ]
    subprocess.run(ssh_command)

def select_random_region(vars_file):
    """Select a random AWS region from the aws_region_choices in vars.yaml."""
    with open(vars_file, "r") as file:
        vars_data = yaml.safe_load(file)
        region_choices = vars_data.get("aws_region_choices", [])
        if not region_choices:
            raise ValueError("No AWS region choices defined in vars.yaml.")
        return random.choice(region_choices)
    
def cleanup_resources(provider, playbook_dir, vars_file, instance_label, aws_creds=None, linode_token=None):
    """
    Cleanup resources if the playbook execution fails.
    """
    print(f"Cleaning up resources for provider: {provider}")

    # Select the appropriate cleanup playbook
    cleanup_playbook = os.path.join(
        playbook_dir,
        "aws-c2-cleanup.yaml" if provider == "aws" else "c2-cleanup.yaml"
    )

    # Build the cleanup command
    cleanup_command = [
        "ansible-playbook", "-i", "localhost,", cleanup_playbook,
        "-e", f"@{vars_file}",  # Use the vars file for base configuration
        "-e", f"instance_label={instance_label}"  # Pass the instance label for cleanup
    ]

    # Add AWS credentials if provided
    if provider == "aws" and aws_creds:
        cleanup_command.extend([
            "-e", f"aws_access_key={aws_creds['access_key']}",
            "-e", f"aws_secret_key={aws_creds['secret_key']}"
        ])
        if aws_creds.get("session_token"):
            cleanup_command.extend(["-e", f"aws_session_token={aws_creds['session_token']}"])

    # Add Linode token if provided
    if provider == "linode" and linode_token:
        cleanup_command.extend(["-e", f"linode_token={linode_token}"])

    try:
        # Run the cleanup playbook
        subprocess.run(cleanup_command, check=True)
        print("Cleanup completed successfully.")
    except subprocess.CalledProcessError as cleanup_error:
        print(f"Error during cleanup: {cleanup_error}")
        raise

def select_region(vars_file, region_arg):
    """Select the AWS region dynamically or use the provided region."""
    if region_arg:
        print(f"Using specified AWS region: {region_arg}")
        return region_arg
    else:
        with open(vars_file, "r") as file:
            vars_data = yaml.safe_load(file)
            region_choices = vars_data.get("aws_region_choices", [])
            if not region_choices:
                raise ValueError("No AWS region choices defined in vars.yaml.")
            selected_region = random.choice(region_choices)
            print(f"Randomly selected AWS region: {selected_region}")
            return selected_region
            
def run_ansible_playbook(playbook, vars_file, public_key_path, private_key_path, instance_label, selected_region, debug, aws_creds=None):
    """Run the Ansible playbook with the provided variables."""
    print(f"Running Ansible playbook: {playbook}")
    
    verbosity = "-vvv" if debug else ""
    command = [
        "ansible-playbook",
        "-i", "localhost,",  # Static inventory for localhost
        playbook,
        "-e", f"@{vars_file}",  # Provider-specific vars.yaml
        "-e", f"ssh_key_path={public_key_path}",  # SSH public key
        "-e", f"private_key_path={private_key_path}",  # SSH private key
        "-e", f"instance_label={instance_label}",  # Instance label
        "-e", f"selected_aws_region={selected_region}"  # Pass the AWS region
    ]

    # Include AWS credentials if provided
    if aws_creds:
        command.extend([
            "-e", f"aws_access_key={aws_creds['access_key']}",
            "-e", f"aws_secret_key={aws_creds['secret_key']}"
        ])
        if aws_creds.get("session_token"):
            command.extend(["-e", f"aws_session_token={aws_creds['session_token']}"])

    if verbosity:
        command.append(verbosity)  # Add verbose flag if debug is enabled

    subprocess.run(command, check=True)  # Allow output to print directly

def main():
    parser = argparse.ArgumentParser(
        description="Deploy C2 Server using Ansible.",
        epilog="Choose between Linode or AWS as the deployment provider. Credentials are expected to be provided via the provider's vars file."
    )
    parser.add_argument(
        "--provider",
        choices=["linode", "aws"],
        default="linode",
        help="Choose the provider for deployment (linode or aws). Defaults to linode."
    )
    parser.add_argument(
        "--region",
        help="Specify an AWS region to deploy the instance. If not provided, a random region will be selected."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode for verbose Ansible output (-vvv)."
    )
    parser.add_argument(
        "--ssh",
        action="store_true",
        help="Automatically SSH into the instance after deployment."
    )
    parser.add_argument(
        "--aws-access-key",
        help="AWS access key. If not provided, it is expected in the AWS vars file."
    )
    parser.add_argument(
        "--aws-secret-key",
        help="AWS secret key. If not provided, it is expected in the AWS vars file."
    )
    parser.add_argument(
        "--aws-session-token",
        help="Optional AWS session token for temporary credentials."
    )
    args = parser.parse_args()

    # Generate a random instance label
    instance_label = generate_random_string()
    print(f"Generated random instance label: {instance_label}")

    # Use the instance label as the key name
    key_name = instance_label

    # Generate SSH key pair with the key name
    private_key, public_key = generate_ssh_key(key_name)
    print(f"Generated SSH key: {private_key} and {public_key}")

    # Determine playbook and vars file based on provider
    playbook_dir = "AWS" if args.provider == "aws" else "Linode"
    playbook = os.path.join(playbook_dir, "aws-c2-deploy.yaml" if args.provider == "aws" else "c2-deploy.yaml")
    vars_file = os.path.join(playbook_dir, "vars.yaml")

    # Select region dynamically or use specified region
    selected_region = select_region(vars_file, args.region)

    # Run the Ansible playbook
    try:
        run_ansible_playbook(
            playbook,
            vars_file,
            public_key,
            private_key,
            instance_label,
            selected_region,
            args.debug,
            aws_creds={
                "access_key": args.aws_access_key,
                "secret_key": args.aws_secret_key,
                "session_token": args.aws_session_token
            } if args.provider == "aws" else None
        )

        # Optionally SSH into the instance
        if args.ssh:
            print(f"SSH into the instance manually using the private key: {private_key}")

    except subprocess.CalledProcessError as e:
        print("Playbook execution failed. Cleaning up resources...")
        cleanup_resources(playbook_dir, vars_file, instance_label, args)

if __name__ == "__main__":
    main()