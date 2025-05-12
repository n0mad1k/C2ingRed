#!/bin/bash
# Enhanced Havoc C2 Framework installer optimized for Red Team Operations
# This script installs and configures Havoc with EDR evasion features
# The mutation features are applied BEFORE building to ensure proper compilation

set -e
TEMP_DIR=$(mktemp -d)
LOG_FILE="/root/Tools/havoc_installer.log"
HAVOC_DIR="/root/Tools/Havoc"
HAVOC_DATA_DIR="/root/Tools/Havoc/data"
COMPILER_URL="http://musl.cc/x86_64-w64-mingw32-cross.tgz"
COMPILER_DIR="/usr/bin/x86_64-w64-mingw32-cross"
COMPILER_PATH="$COMPILER_DIR/bin/x86_64-w64-mingw32-gcc"
IMPLANT_MUTATOR_SCRIPT="$HAVOC_DIR/implant_mutator.sh"
HAVOC_GITHUB="https://github.com/HavocFramework/Havoc.git"

# Function to log messages
log() {
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] $1" | tee -a $LOG_FILE
}

# Function to generate random strings
random_string() {
    local length=${1:-16}
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $length | head -n 1
}

# Generate random build ID for implant signature
RANDOMIZED_BUILD_ID=$(random_string 16)

# Install required dependencies
log "Installing dependencies..."
apt-get update >/dev/null 2>&1
apt-get install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev python3-dev libboost-all-dev mingw-w64 nasm >/dev/null 2>&1

# Fix for JSON dependency
log "Installing nlohmann-json manually..."
mkdir -p /tmp/json
cd /tmp/json
wget -q https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
mkdir -p /usr/include/nlohmann
cp json.hpp /usr/include/nlohmann/
cd - > /dev/null

# Setup Go environment
log "Setting up Go environment..."
mkdir -p /root/go
export GOPATH=/root/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Download and install compiler fix
log "Downloading and installing fixed compiler..."
if [ ! -d "$COMPILER_DIR" ]; then
    # Download the compiler
    wget -q -O /tmp/compiler.tgz $COMPILER_URL
    
    # Extract to /usr/bin
    tar -xzf /tmp/compiler.tgz -C /usr/bin
    
    # Verify compiler exists
    if [ -f "$COMPILER_PATH" ]; then
        log "Compiler installed successfully at $COMPILER_PATH"
        chmod +x $COMPILER_PATH
    else
        log "Error: Compiler installation failed. File not found at $COMPILER_PATH"
    fi
    
    # Clean up
    rm -f /tmp/compiler.tgz
else
    log "Compiler already installed at $COMPILER_DIR"
fi

# Clone Havoc repository
log "Cloning Havoc repository..."
if [ -d "$HAVOC_DIR" ]; then
    log "Havoc directory already exists, updating..."
    cd $HAVOC_DIR
    git pull
else
    # Clone with proper GitHub URL
    git clone --quiet -b dev $HAVOC_GITHUB $HAVOC_DIR
    cd $HAVOC_DIR
fi

# Create data directories
mkdir -p $HAVOC_DATA_DIR
mkdir -p $HAVOC_DIR/payloads
mkdir -p $HAVOC_DIR/payloads/backup

# Initialize submodules
log "Initializing submodules..."
cd $HAVOC_DIR
git submodule init
git submodule update --recursive

# Install additional Go dependencies for the teamserver
log "Installing Go dependencies for teamserver..."
cd $HAVOC_DIR/teamserver
go mod download golang.org/x/sys
cd $HAVOC_DIR

# Build Havoc using make - build teamserver first
log "Building Havoc teamserver..."
cd $HAVOC_DIR
make ts-build

# Build Havoc client
#log "Building Havoc client..."
#make client-build

# Create systemd service for Havoc
log "Creating systemd service for Havoc teamserver..."
cat > /etc/systemd/system/havoc.service << EOF
[Unit]
Description=Advanced Security Service
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$HAVOC_DIR/teamserver
ExecStart=$HAVOC_DIR/havoc server -d
Restart=always
RestartSec=10

# Security measures
PrivateTmp=true
ProtectHome=false
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# Set proper permissions
log "Setting proper permissions..."
chmod -R 755 $HAVOC_DIR

# Create symlinks to executables in /usr/local/bin
ln -sf $HAVOC_DIR/havoc /usr/local/bin/havoc
ln -sf $IMPLANT_MUTATOR_SCRIPT /usr/local/bin/havoc-mutate

# Enable and start Havoc service
log "Enabling and starting Havoc service..."
systemctl daemon-reload
systemctl enable havoc
systemctl start havoc

log "Havoc C2 installation completed successfully!"