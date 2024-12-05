import os
import subprocess
import argparse
import random
import string

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

def run_ansible_playbook(playbook, vars_file, public_key_path, private_key_path, instance_label, debug, aws_creds=None, linode_token=None):
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
        "-e", f"instance_label={instance_label}"  # Instance label
    ]

    # Include AWS credentials if provided
    if aws_creds:
        command.extend([
            "-e", f"aws_access_key={aws_creds['access_key']}",
            "-e", f"aws_secret_key={aws_creds['secret_key']}"
        ])

    # Include Linode token if provided
    if linode_token:
        command.extend(["-e", f"linode_token={linode_token}"])

    if verbosity:
        command.append(verbosity)  # Add verbose flag if debug is enabled

    subprocess.run(command, check=True)

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
        "--debug",
        action="store_true",
        help="Enable debug mode for verbose Ansible output (-vvv)."
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
        "--linode-token",
        help="Linode API token. If not provided, it is expected in the Linode vars file."
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

    # Run the Ansible playbook
    try:
        run_ansible_playbook(
            playbook,
            vars_file,
            public_key,
            private_key,
            instance_label,
            args.debug,
            aws_creds={
                "access_key": args.aws_access_key,
                "secret_key": args.aws_secret_key
            } if args.provider == "aws" else None,
            linode_token=args.linode_token if args.provider == "linode" else None
        )
    except subprocess.CalledProcessError:
        print("Playbook execution failed. Cleaning up resources...")
        cleanup_playbook = os.path.join(
            playbook_dir,
            "aws-c2-cleanup.yaml" if args.provider == "aws" else "c2-cleanup.yaml"
        )
        cleanup_command = [
            "ansible-playbook", "-i", "localhost,", cleanup_playbook,
            "-e", f"@{vars_file}",
            "-e", f"instance_label={instance_label}"
        ]
        subprocess.run(cleanup_command, check=False)
        raise

if __name__ == "__main__":
    main()
