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
    """Generate an SSH key with a name based on the current date and a random string."""
    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, exist_ok=True)

    # Format key name as YYYY-MM-DD-randomstring
    key_name = f"{datetime.now().strftime('%Y-%m-%d')}-{generate_random_string()}"
    private_key_path = os.path.join(ssh_dir, key_name)
    public_key_path = f"{private_key_path}.pub"

    print(f"Generating SSH key: {key_name}")
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", private_key_path, "-N", ""],
        check=True
    )

    return private_key_path, public_key_path

def run_ansible_playbook(playbook, vars_file, public_key_path, instance_label, debug):
    """Run the Ansible playbook with the provided variables."""
    print(f"Running Ansible playbook: {playbook}")
    verbosity = "-vvv" if debug else ""
    command = [
        "ansible-playbook", "-i", "localhost,", playbook,
        "-e", f"@{vars_file}",
        "-e", f"ssh_key_path={public_key_path}",
        "-e", f"instance_label={instance_label}"
    ]
    if verbosity:
        command.append(verbosity)
    subprocess.run(command, check=True)

def main():
    parser = argparse.ArgumentParser(
        description="Deploy C2 Server using Ansible.",
        epilog="If no arguments are provided, the script will use default values: "
               "'c2-vars.yaml' for vars file and 'c2-deploy.yaml' for the playbook."
    )
    parser.add_argument(
        "--vars-file",
        default="c2-vars.yaml",  # Default value if not provided
        help="Path to the variables file. Defaults to 'c2-vars.yaml'."
    )
    parser.add_argument(
        "--playbook",
        default="c2-deploy.yaml",  # Default value if not provided
        help="Path to the Ansible playbook. Defaults to 'c2-deploy.yaml'."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode for verbose Ansible output (-vvv)."
    )
    args = parser.parse_args()

    private_key, public_key = generate_ssh_key()
    print(f"Generated SSH key: {private_key} and {public_key}")

    instance_label = generate_random_string(12)
    print(f"Generated random instance label: {instance_label}")

    run_ansible_playbook(args.playbook, args.vars_file, public_key, instance_label, args.debug)

if __name__ == "__main__":
    main()
