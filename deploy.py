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
    """
    Fetch the public IP of an instance based on its label and provider.
    """
    print(f"Fetching instance IP for label: {instance_label} (Provider: {provider})")
    
    try:
        if provider == "aws":
            result = subprocess.check_output(
                [
                    "aws", "ec2", "describe-instances",
                    "--filters", f"Name=tag:Name,Values={instance_label}", "Name=instance-state-name,Values=running",
                    "--query", "Reservations[*].Instances[*].PublicIpAddress",
                    "--output", "text"
                ],
                text=True
            ).strip()
            if result:
                print(f"Instance IP: {result}")
                return result
            else:
                raise ValueError("No IP found for the instance.")
        elif provider == "linode":
            result = subprocess.check_output(
                ["linode-cli", "linodes", "list", "--label", instance_label, "--json"],
                text=True
            ).strip()
            linodes = json.loads(result)
            if linodes and "ipv4" in linodes[0]:
                ip_address = linodes[0]["ipv4"][0]  # Extract the first IPv4 address
                print(f"Instance IP: {ip_address}")
                return ip_address
            else:
                raise ValueError("No IP found for the instance.")
        else:
            raise ValueError(f"Unsupported provider: {provider}")
    except subprocess.CalledProcessError as e:
        print(f"Error fetching instance IP: {e}")
        raise ValueError(f"Error fetching instance IP for provider {provider}: {e}")
    
    raise ValueError("Could not determine instance IP after multiple retries.")

def ssh_into_instance(private_key_path, ip_address, username="root"):
    """SSH into the deployed instance."""
    print(f"Connecting to {username}@{ip_address}...")
    ssh_command = [
        "ssh",
        "-i", private_key_path,
        f"{username}@{ip_address}"
    ]
    subprocess.run(ssh_command)

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

def cleanup_resources(provider, instance_label, private_key_path=None):
    """
    Cleanup resources by terminating instances and deleting keys from the provider and local files.
    """
    print(f"Starting cleanup for provider: {provider}, instance label: {instance_label}")

    # Cleanup for AWS
    if provider == "aws":
        # Terminate the instance
        try:
            print(f"Fetching AWS instance ID for label: {instance_label}")
            instance_id = subprocess.check_output(
                [
                    "aws", "ec2", "describe-instances",
                    "--filters", f"Name=tag:Name,Values={instance_label}", "Name=instance-state-name,Values=running",
                    "--query", "Reservations[].Instances[].InstanceId",
                    "--output", "text"
                ],
                text=True
            ).strip()

            if instance_id:
                print(f"Terminating AWS instance ID: {instance_id}")
                subprocess.run(
                    ["aws", "ec2", "terminate-instances", "--instance-ids", instance_id],
                    check=True
                )
                print(f"AWS instance {instance_id} terminated successfully.")
            else:
                print("No running AWS instances found for the given label.")
        except Exception as e:
            print(f"Error during AWS instance termination: {e}")

        # Delete the key pair
        try:
            print(f"Deleting AWS key pair: {instance_label}")
            subprocess.run(
                ["aws", "ec2", "delete-key-pair", "--key-name", instance_label],
                check=True
            )
            print(f"AWS key pair {instance_label} deleted successfully.")
        except Exception as e:
            print(f"Error deleting AWS key pair: {e}")

    # Cleanup for Linode
    elif provider == "linode":
        # Delete the Linode instance
        try:
            print(f"Deleting Linode instance with label: {instance_label}")
            subprocess.run(
                ["linode-cli", "linodes", "delete", instance_label],
                check=True
            )
            print(f"Linode instance {instance_label} deleted successfully.")
        except Exception as e:
            print(f"Error during Linode instance deletion: {e}")

        # Delete the SSH key
        try:
            print(f"Fetching Linode SSH key ID for label: {instance_label}")
            ssh_key_list = subprocess.check_output(
                ["linode-cli", "ssh-keys", "list", "--json"],
                text=True
            )
            ssh_keys = json.loads(ssh_key_list)
            key_id = next(
                (key["id"] for key in ssh_keys if key["label"] == instance_label), 
                None
            )

            if key_id:
                print(f"Deleting Linode SSH key ID: {key_id}")
                subprocess.run(
                    ["linode-cli", "ssh-keys", "delete", str(key_id)],
                    check=True
                )
                print(f"Linode SSH key {instance_label} deleted successfully.")
            else:
                print(f"No matching SSH key found in Linode with label {instance_label}.")
        except Exception as e:
            print(f"Error deleting Linode SSH key: {e}")

    # Cleanup local key files
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
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for verbose Ansible output (-vvv).")
    parser.add_argument("--ssh", action="store_true", help="Automatically SSH into the instance after deployment.")
    parser.add_argument("--aws-access-key", help="AWS access key. If not provided, it is expected in the AWS vars file.")
    parser.add_argument("--aws-secret-key", help="AWS secret key. If not provided, it is expected in the AWS vars file.")
    parser.add_argument("--aws-session-token", help="Optional AWS session token for temporary credentials.")
    args = parser.parse_args()

    instance_label = generate_random_string()
    print(f"Generated random instance label: {instance_label}")
    key_name = instance_label
    private_key, public_key = generate_ssh_key(key_name)

    playbook_dir = "AWS" if args.provider == "aws" else "Linode"
    playbook = os.path.join(playbook_dir, "aws-c2-deploy.yaml" if args.provider == "aws" else "c2-deploy.yaml")
    vars_file = os.path.join(playbook_dir, "vars.yaml")
    selected_region = select_region(vars_file, args.region, args.provider)

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
        if args.ssh:
            ip_address = fetch_instance_ip(args.provider, instance_label)
            ssh_into_instance(private_key, ip_address, "kali" if args.provider == "aws" else "root")
    except subprocess.CalledProcessError:
        cleanup_resources(
            args.provider,
            playbook_dir,
            vars_file,
            instance_label,
            aws_creds={
                "access_key": args.aws_access_key,
                "secret_key": args.aws_secret_key,
                "session_token": args.aws_session_token
            } if args.provider == "aws" else None
        )

if __name__ == "__main__":
    main()
