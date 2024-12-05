import os
import subprocess
import argparse
import random
import string
from datetime import datetime

# Disable Ansible host key checking
os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"

def generate_random_string(length=6):
    """Generate a random string of letters and digits."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_ssh_key():
    """Generate an SSH key with no user information in the comment."""
    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, exist_ok=True)

    # Format key name as YYYY-MM-DD-randomstring
    key_name = f"{datetime.now().strftime('%Y-%m-%d')}-{generate_random_string()}"
    private_key_path = os.path.join(ssh_dir, key_name)
    public_key_path = f"{private_key_path}.pub"

    print(f"Generating SSH key: {key_name}")
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", private_key_path, "-N", "", "-C", ""],
        check=True
    )

    return private_key_path, public_key_path

def run_ansible_playbook(playbook, vars_file, public_key_path, instance_label, debug):
    """Run the Ansible playbook with the provided variables."""
    print(f"Running Ansible playbook: {playbook}")
    
    verbosity = "-vvv" if debug else ""
    command = [
        "ansible-playbook", 
        "-i", "localhost,",  # Static inventory for localhost
        playbook,  # Ansible playbook file
        "-e", f"@{vars_file}",  # Variable file
        "-e", f"ssh_key_path={public_key_path}",  # SSH public key
        "-e", f"private_key_path={public_key_path.replace('.pub', '')}",  # SSH private key
        "-e", f"instance_label={instance_label}"  # Instance label
    ]

    if verbosity:
        command.append(verbosity)  # Add verbose flag if debug is enabled

    # Dynamically run the command
    subprocess.run(command, check=True)

def delete_linode_instance(instance_label, linode_token):
    """Delete the Linode instance using its label."""
    print(f"Deleting Linode instance with label: {instance_label}")
    command = [
        "ansible-playbook", 
        "-i", "localhost,", 
        "cleanup.yaml",  # A new playbook to delete Linode instance
        "-e", f"linode_token={linode_token}",
        "-e", f"instance_label={instance_label}"
    ]
    try:
        subprocess.run(command, check=True)
        print(f"Successfully deleted Linode instance: {instance_label}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to delete Linode instance: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Deploy C2 Server using Ansible.",
        epilog="If no arguments are provided, the script will use default values: "
               "'c2-vars.yaml' for vars file and 'c2-deploy.yaml' for the playbook."
    )
    parser.add_argument("--vars-file", default="c2-vars.yaml", help="Path to the variables file.")
    parser.add_argument("--playbook", default="c2-deploy.yaml", help="Path to the Ansible playbook.")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for verbose Ansible output (-vvv).")
    parser.add_argument("--linode-token", required=True, help="Linode API token for managing instances.")
    args = parser.parse_args()

    private_key, public_key = generate_ssh_key()
    print(f"Generated SSH key: {private_key} and {public_key}")

    instance_label = generate_random_string(12)
    print(f"Generated random instance label: {instance_label}")

    try:
        # Run the Ansible playbook
        run_ansible_playbook(args.playbook, args.vars_file, public_key, instance_label, args.debug)
    except subprocess.CalledProcessError:
        # Cleanup on failure
        print("Playbook execution failed. Cleaning up resources...")
        delete_linode_instance(instance_label, args.linode_token)
        raise

if __name__ == "__main__":
    main()
