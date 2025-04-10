import os
import subprocess
import argparse
import random
import string
import json
import yaml
import time

# Disable Ansible host key checking
os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"

def get_linode_token(vars_file):
    with open(vars_file, "r") as file:
        vars_data = yaml.safe_load(file)
        return vars_data.get("linode_token")

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

def fetch_instance_ip(provider, instance_label, linode_token=None, aws_creds=None):

    print(f"Fetching instance IP for label: {instance_label} (Provider: {provider})")
    
    try:
        if provider == "aws":
            if not aws_creds or not aws_creds.get("access_key") or not aws_creds.get("secret_key"):
                raise ValueError("AWS credentials are required for fetching instance IP.")
            
            # Prepare environment variables with AWS credentials
            env_vars = os.environ.copy()
            env_vars["AWS_ACCESS_KEY_ID"] = aws_creds["access_key"]
            env_vars["AWS_SECRET_ACCESS_KEY"] = aws_creds["secret_key"]
            if aws_creds.get("session_token"):
                env_vars["AWS_SESSION_TOKEN"] = aws_creds["session_token"]
            
            # Execute the AWS CLI command with the provided credentials
            print("Executing AWS CLI command to fetch instance IP...")
            result = subprocess.check_output(
                [
                    "aws", "ec2", "describe-instances",
                    "--filters", f"Name=tag:Name,Values={instance_label}", "Name=instance-state-name,Values=running",
                    "--query", "Reservations[*].Instances[*].PublicIpAddress",
                    "--output", "text"
                ],
                text=True,
                env=env_vars
            ).strip()
            
            if result:
                print(f"Instance IP: {result}")
                return result
            else:
                raise ValueError("No IP address found for the instance.")
        
        elif provider == "linode":
            if not linode_token:
                raise ValueError("Linode token is required for fetching instance IP.")
            
            # Set LINODE_CLI_TOKEN in the environment
            env_vars = os.environ.copy()
            env_vars["LINODE_CLI_TOKEN"] = linode_token

            # Run linode-cli with the token
            print("Executing linode-cli command...")
            result = subprocess.check_output(
                ["linode-cli", "linodes", "list", "--label", instance_label, "--json"],
                text=True,
                env=env_vars
            ).strip()
            print(f"linode-cli output: {result}")
            linodes = json.loads(result)
            if linodes and "ipv4" in linodes[0] and linodes[0]["ipv4"]:
                ip_address = linodes[0]["ipv4"][0]  # Extract the first IPv4 address
                print(f"Instance IP: {ip_address}")
                return ip_address
            else:
                raise ValueError("No IP address found for the instance.")
        else:
            raise ValueError(f"Unsupported provider: {provider}")
    except subprocess.CalledProcessError as e:
        print(f"Error fetching instance IP: {e}")
        raise ValueError(f"Error fetching instance IP for provider {provider}: {e}")
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON output: {e}")
        raise ValueError(f"Invalid JSON response when fetching instance IP for provider {provider}: {e}")

def ssh_into_instance(private_key_path, ip_address, username="root"):
    """
    SSH into the deployed instance. Retry with -o IdentitiesOnly=yes if the first attempt fails.
    """
    ssh_command = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-i", private_key_path,
        f"{username}@{ip_address}"
    ]

    print(f"Attempting SSH connection to {username}@{ip_address}...")

    try:
        subprocess.run(ssh_command, check=True)
    except subprocess.CalledProcessError:
        print("Initial SSH connection failed. Retrying with -o IdentitiesOnly=yes...")
        ssh_command.insert(1, "-o")
        ssh_command.insert(2, "IdentitiesOnly=yes")
        try:
            subprocess.run(ssh_command, check=True)
        except subprocess.CalledProcessError as e:
            print(f"SSH connection failed after retry: {e}")
            raise e

def select_region(vars_file, region_arg, provider):
    """Select the region dynamically for the provider or use the provided region."""
    if region_arg:
        print(f"Using specified {provider.upper()} region: {region_arg}")
        return region_arg
    else:
        with open(vars_file, "r") as file:
            vars_data = yaml.safe_load(file)
            region_choices = vars_data.get("region_choices", [])
            if not region_choices:
                raise ValueError(f"No region choices defined in {vars_file}.")
            selected_region = random.choice(region_choices)
            print(f"Randomly selected {provider.upper()} region: {selected_region}")
            return selected_region

def run_ansible_playbook(playbook, vars_file, public_key_path, private_key_path, instance_label, selected_region, debug, aws_creds=None, ssh_user="root"):
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
        "-e", f"ssh_user={ssh_user}"  # Pass the SSH user dynamically
    ]
    if selected_region:
        command.append(f"-e selected_aws_region={selected_region}")
    if aws_creds:
        command.extend([
            "-e", f"aws_access_key={aws_creds['access_key']}",
            "-e", f"aws_secret_key={aws_creds['secret_key']}"
        ])
        if aws_creds.get("session_token"):
            command.extend(["-e", f"aws_session_token={aws_creds['session_token']}"])

    if verbosity:
        command.append(verbosity)

    subprocess.run(command, check=True)

def run_command(command, env=None, error_msg="Command failed", debug=False):
    """Run a shell command and return its output."""
    try:
        if debug:
            print(f"Running command: {' '.join(command)}")
            if env:
                print(f"Environment Variables: {env}")
        
        result = subprocess.check_output(command, text=True, env=env).strip()
        
        if debug:
            print(f"Command output: {result}")
        
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        if debug and e.output:
            print(f"Command output: {e.output}")
        raise RuntimeError(f"{error_msg}: {str(e)}")

def cleanup_resources(provider, instance_label, private_key_path=None, aws_creds=None, debug=False):
    """
    Cleanup resources by terminating instances and deleting keys from the provider and local files.
    """
    print(f"Starting cleanup for provider: {provider}, instance label: {instance_label}")

    # AWS-specific cleanup
    if provider == "aws" and aws_creds:
        env_vars = {
            **os.environ,
            "AWS_ACCESS_KEY_ID": aws_creds.get("access_key"),
            "AWS_SECRET_ACCESS_KEY": aws_creds.get("secret_key")
        }

        # Add AWS_SESSION_TOKEN only if it's not None
        if aws_creds.get("session_token"):
            env_vars["AWS_SESSION_TOKEN"] = aws_creds["session_token"]

        try:
            print(f"Fetching AWS instance ID for label: {instance_label}")
            instance_id = run_command(
                [
                    "aws", "ec2", "describe-instances",
                    "--filters", f"Name=tag:Name,Values={instance_label}",
                    "--query", "Reservations[].Instances[].InstanceId",
                    "--output", "text"
                ],
                env=env_vars,
                error_msg="Error during AWS instance fetch",
                debug=debug
            )

            if instance_id:
                print(f"Terminating AWS instance ID: {instance_id}")
                run_command(
                    [
                        "aws", "ec2", "terminate-instances",
                        "--instance-ids", instance_id
                    ],
                    env=env_vars,
                    error_msg="Error during AWS instance termination",
                    debug=debug
                )
                print(f"AWS instance {instance_id} terminated successfully.")
            else:
                print("No instance ID found for the given label. Skipping termination.")

        except Exception as e:
            print(f"Error during AWS instance termination: {e}")

        # Delete the key pair
        try:
            print(f"Deleting AWS key pair: {instance_label}")
            run_command(
                [
                    "aws", "ec2", "delete-key-pair",
                    "--key-name", instance_label
                ],
                env=env_vars,
                error_msg="Error deleting AWS key pair",
                debug=debug
            )
            print(f"AWS key pair {instance_label} deleted successfully.")
        except Exception as e:
            print(f"Error deleting AWS key pair: {e}")

    # Linode-specific cleanup
    elif provider == "linode":
            # Assuming vars_file is accessible or passed globally; adjust as needed
            vars_file = "Linode/vars.yaml"  # Adjust path if needed
            linode_token = get_linode_token(vars_file)
            
            if not linode_token:
                print("No linode_token found in vars.yaml. Cleanup may fail due to authentication.")
            
            linode_env = {**os.environ}
            if linode_token:
                linode_env["LINODE_CLI_TOKEN"] = linode_token

            try:
                print(f"Fetching Linode instance ID for label: {instance_label}")
                linodes_json = run_command(
                    ["linode-cli", "linodes", "list", "--label", instance_label, "--json"],
                    env=linode_env,
                    error_msg="Error fetching Linode instances",
                    debug=debug
                )

                linodes = json.loads(linodes_json)
                if not linodes:
                    print(f"No instance found with label: {instance_label}")
                else:
                    instance_id = linodes[0]["id"]
                    print(f"Found Linode ID: {instance_id}")

                    print(f"Deleting Linode instance with ID: {instance_id}")
                    run_command(
                        ["linode-cli", "linodes", "delete", str(instance_id)],
                        env=linode_env,
                        error_msg="Error deleting Linode instance",
                        debug=debug
                    )
                    print(f"Linode instance {instance_id} deleted successfully.")
            except Exception as e:
                print(f"Error during Linode instance deletion: {e}")

            try:
                print(f"Fetching Linode SSH key ID for label: {instance_label}")
                ssh_key_list = run_command(
                    ["linode-cli", "ssh-keys", "list", "--json"],
                    env=linode_env,
                    error_msg="Error fetching Linode SSH keys",
                    debug=debug
                )
                ssh_keys = json.loads(ssh_key_list)
                key_id = next((key["id"] for key in ssh_keys if key["label"] == instance_label), None)

                if key_id:
                    print(f"Deleting Linode SSH key ID: {key_id}")
                    run_command(
                        ["linode-cli", "ssh-keys", "delete", str(key_id)],
                        env=linode_env,
                        error_msg="Error deleting Linode SSH key",
                        debug=debug
                    )
                    print(f"Linode SSH key {instance_label} deleted successfully.")
                else:
                    print(f"No matching SSH key found in Linode with label {instance_label}.")
            except Exception as e:
                print(f"Error deleting Linode SSH key: {e}")

    # Local key file cleanup
    try:
        if private_key_path:
            files_to_delete = [
                private_key_path,
                f"{private_key_path}.pub",
                f"{private_key_path}.pem"
            ]
            for file in files_to_delete:
                if os.path.exists(file):
                    os.remove(file)
                    print(f"Deleted local key file: {file}")
                else:
                    print(f"Local key file not found: {file}")
    except Exception as e:
        print(f"Error during local key file cleanup: {e}")

    print("Cleanup completed.")

def main():
    parser = argparse.ArgumentParser(
        description="Deploy C2 Server using Ansible.",
        epilog="Choose between Linode or AWS as the deployment provider. Credentials are expected to be provided via the provider's vars file."
    )
    parser.add_argument("--provider", choices=["linode", "aws"], default="linode", help="Choose the provider for deployment (linode or aws). Defaults to linode.")
    parser.add_argument("--region", help="Specify a region to deploy the instance. If not provided, a random region will be selected.")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for verbose command and Ansible output.")
    parser.add_argument("--ssh", action="store_true", help="Automatically SSH into the instance after deployment.")
    parser.add_argument("--aws-access-key", help="AWS access key. If not provided, it is expected in the AWS vars file.")
    parser.add_argument("--aws-secret-key", help="AWS secret key. If not provided, it is expected in the AWS vars file.")
    parser.add_argument("--aws-session-token", help="Optional AWS session token for temporary credentials.")
    args = parser.parse_args()

    # Generate a random label for the instance
    instance_label = generate_random_string()
    print(f"Generated random instance label: {instance_label}")
    key_name = instance_label

    # Generate SSH keys
    private_key, public_key = generate_ssh_key(key_name)

    # Set playbook paths based on provider
    playbook_dir = "AWS" if args.provider == "aws" else "Linode"
    playbook = os.path.join(playbook_dir, "aws-c2-deploy.yaml" if args.provider == "aws" else "c2-deploy.yaml")
    vars_file = os.path.join(playbook_dir, "vars.yaml")

    # Select region
    selected_region = select_region(vars_file, args.region, args.provider)

    # Retrieve Linode token if provider is Linode
    linode_token = None
    if args.provider == "linode":
        linode_token = get_linode_token(vars_file)
        if not linode_token:
            print("Error: 'linode_token' not found in vars.yaml.")
            exit(1)

    try:
        # Run Ansible playbook
        run_ansible_playbook(
            playbook=playbook,
            vars_file=vars_file,
            public_key_path=public_key,
            private_key_path=private_key,
            instance_label=instance_label,
            selected_region=selected_region,
            debug=args.debug,
            aws_creds={
                "access_key": args.aws_access_key,
                "secret_key": args.aws_secret_key,
                "session_token": args.aws_session_token
            } if args.provider == "aws" else None
        )

        # SSH into the instance if requested
        if args.ssh:
            if args.provider == "aws":
                ip_address = fetch_instance_ip(
                    provider=args.provider,
                    instance_label=instance_label,
                    aws_creds={
                        "access_key": args.aws_access_key,
                        "secret_key": args.aws_secret_key,
                        "session_token": args.aws_session_token
                    }
                )
            elif args.provider == "linode":
                ip_address = fetch_instance_ip(
                    provider=args.provider,
                    instance_label=instance_label,
                    linode_token=linode_token
                )

        # Dynamically set the SSH private key path
            ssh_dir = os.path.expanduser("~/.ssh")
            ssh_private_key = f"{ssh_dir}/{instance_label}.pem" if args.provider == "aws" else f"{ssh_dir}/{instance_label}"
    
            ssh_into_instance(
                private_key_path=ssh_private_key,
                ip_address=ip_address,
                username="kali" if args.provider == "aws" else "root"
            )

    except subprocess.CalledProcessError as e:
        # Handle deployment errors by running cleanup
        print(f"Deployment failed: {e}. Initiating cleanup...")
        cleanup_resources(
            provider=args.provider,
            instance_label=instance_label,
            private_key_path=private_key,
            aws_creds={
                "access_key": args.aws_access_key,
                "secret_key": args.aws_secret_key,
                "session_token": args.aws_session_token
            } if args.provider == "aws" else None,
            debug=args.debug
        )
    except Exception as e:
        # Catch any other exceptions and perform cleanup
        print(f"An unexpected error occurred: {e}. Initiating cleanup...")
        cleanup_resources(
            provider=args.provider,
            instance_label=instance_label,
            private_key_path=private_key,
            aws_creds={
                "access_key": args.aws_access_key,
                "secret_key": args.aws_secret_key,
                "session_token": args.aws_session_token
            } if args.provider == "aws" else None,
            debug=args.debug
        )
    else:
        # Clean exit if everything succeeds
        print(f"Deployment and configuration for {args.provider.upper()} completed successfully!")

if __name__ == "__main__":
    main()
