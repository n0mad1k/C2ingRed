#!/bin/bash
# Script to securely clean the system before shutdown

# 1. Stop all services
systemctl stop sliver-server
systemctl stop shell-handler

# 2. Secure delete sensitive files
find /opt/c2/implants -type f -not -name "*.enc" -exec shred -uz {} \; 2>/dev/null
find /opt/c2/loot -type f -exec shred -uz {} \; 2>/dev/null
find /opt/c2/shells -type f -exec shred -uz {} \; 2>/dev/null

# 3. Clear bash history
history -c
rm -f ~/.bash_history

# 4. Clear memory
echo 3 > /proc/sys/vm/drop_caches

# 5. Overwrite free space in critical directories
dd if=/dev/urandom of=/opt/c2/wipe.bin bs=1M count=10 2>/dev/null
shred -uz /opt/c2/wipe.bin 2>/dev/null