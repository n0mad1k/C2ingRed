#!/bin/bash
# Clean up any potentially created logs

# Clear existing log files
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
find /var/log -type f -name "*.log.*" -exec rm -f {} \;
find /var/log -type f -name "*.gz" -exec rm -f {} \;

# Clear journal logs
rm -rf /var/log/journal/*
rm -rf /run/log/journal/*

# Clear auth logs
truncate -s 0 /var/log/auth.log 2>/dev/null
truncate -s 0 /var/log/secure 2>/dev/null

# Clear bash history for all users
find /home -name ".bash_history" -exec truncate -s 0 {} \; 2>/dev/null
find /root -name ".bash_history" -exec truncate -s 0 {} \; 2>/dev/null

# Clear temporary files
rm -rf /tmp/* 2>/dev/null
rm -rf /var/tmp/* 2>/dev/null

# Clear recently used files lists
find /home -name ".recently-used" -exec truncate -s 0 {} \; 2>/dev/null
find /root -name ".recently-used" -exec truncate -s 0 {} \; 2>/dev/null

# Force clear memory cache
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null

# Clear current shell history
history -c 2>/dev/null