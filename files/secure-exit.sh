#!/bin/bash
# Secure cleanup script for terminating the C2 infrastructure

# Configuration
SECURE_DELETE_PASSES=7
MEMORY_WIPE=true
SELF_DESTRUCT=false  # Set to true for complete instance termination (if API available)

# Set secure umask
umask 077

# Function to securely delete files
secure_delete() {
    local target=$1
    echo "[+] Securely deleting: $target"
    
    if command -v srm > /dev/null; then
        srm -vzf $target 2>/dev/null
    elif command -v shred > /dev/null; then
        shred -vzfn $SECURE_DELETE_PASSES $target 2>/dev/null
    else
        # Fallback to dd if specialized tools aren't available
        dd if=/dev/urandom of=$target bs=1M count=10 conv=notrunc 2>/dev/null
        dd if=/dev/zero of=$target bs=1M count=10 conv=notrunc 2>/dev/null
        rm -f $target 2>/dev/null
    fi
}

echo "[+] Beginning secure exit procedure..."

# Stop all operational services
echo "[+] Stopping operational services..."
services=("nginx" "sliver" "shell-handler" "gophish" "metasploit" "postgresql" "tor" "opendkim" "postfix" "dovecot")
for service in "${services[@]}"; do
    systemctl stop $service 2>/dev/null
    service $service stop 2>/dev/null
done

# Kill any remaining operational processes
echo "[+] Terminating operational processes..."
process_names=("nginx" "sliver" "msfconsole" "meterpreter" "ruby" "nc" "netcat" "socat" "python" "tor")
for proc in "${process_names[@]}"; do
    pkill -9 $proc 2>/dev/null
done

# Clear all logs
echo "[+] Clearing logs..."
bash /root/Tools/clean-logs.sh

# Securely delete operational files
echo "[+] Removing operational files..."
operational_dirs=(
    "/root/Tools"
    "/root/Tools/beacons"
    "/root/Tools/payloads"
    "/root/.sliver"
    "/root/.msf4"
    "/root/.gophish"
    "/root/Tools"
    "/home/*/Tools"
    "/var/www/html"
)

for dir in "${operational_dirs[@]}"; do
    find $dir -type f 2>/dev/null | while read file; do
        secure_delete "$file"
    done
    rm -rf $dir 2>/dev/null
done

# Remove SSH keys
echo "[+] Removing SSH keys and configs..."
find /home/*/.ssh /root/.ssh -type f 2>/dev/null | while read file; do
    secure_delete "$file"
done

# Clean memory if requested
if $MEMORY_WIPE; then
    echo "[+] Wiping system memory..."
    sync
    echo 3 > /proc/sys/vm/drop_caches
    swapoff -a
    swapon -a
fi

# Self-destruct if configured (for cloud providers with API access)
if $SELF_DESTRUCT; then
    echo "[+] Initiating self-destruct sequence..."
    # This would typically call the cloud provider's API to terminate the instance
    # For FlokiNET, this would need to be handled manually
fi

echo "[+] Secure exit completed. Infrastructure has been sanitized."

# Remove this script itself
exec shred -n $SECURE_DELETE_PASSES -uz $0