#!/bin/bash
# secure_payload_sync.sh - OPSEC-focused payload distribution

# Configuration
C2_PAYLOAD_DIR="/root/Tools/Havoc/payloads"
REDIRECTOR_IP="{{ redirector_ip }}"
REDIRECTOR_USER="root"
SSH_KEY_PATH="/root/.ssh/id_ed25519"
REMOTE_PAYLOAD_DIR="/var/www/resources"
ENCRYPTED_TRANSFER=true
LOG_FILE="/root/Tools/logs/payload_sync.log"
LOG_RETENTION_DAYS=3
MAX_RANDOM_DELAY=300  # Max random delay in seconds

# Create minimal timestamped log with auto-rotation
log() {
  mkdir -p $(dirname $LOG_FILE)
  echo "$(date "+%Y-%m-%d %H:%M:%S") - $1" >> $LOG_FILE
  find $(dirname $LOG_FILE) -name "*.log" -mtime +$LOG_RETENTION_DAYS -delete 2>/dev/null
}

# Add random delay for OPSEC
sleep_random() {
  DELAY=$((RANDOM % $MAX_RANDOM_DELAY))
  log "Adding random delay of $DELAY seconds"
  sleep $DELAY
}

# Generate payload manifest and check for changes
check_for_changes() {
  if [ ! -d "$C2_PAYLOAD_DIR" ]; then
    log "ERROR: Payload directory not found"
    return 1
  fi
  
  TMP_DIR=$(mktemp -d)
  MANIFEST_FILE="$TMP_DIR/manifest"
  find $C2_PAYLOAD_DIR -type f -exec sha256sum {} \; | sort > $MANIFEST_FILE
  
  CURRENT_HASH=$(sha256sum $MANIFEST_FILE | awk '{print $1}')
  HASH_FILE="/root/Tools/.payload_hash"
  
  if [ -f "$HASH_FILE" ] && [ "$(cat $HASH_FILE)" == "$CURRENT_HASH" ]; then
    log "No payload changes detected"
    secure_delete $TMP_DIR
    return 1
  fi
  
  echo $CURRENT_HASH > $HASH_FILE
  return 0
}

# Secure deletion of files/directories
secure_delete() {
  if [ -d "$1" ]; then
    find "$1" -type f -exec shred -n 3 -z -u {} \; 2>/dev/null
    rm -rf "$1" 2>/dev/null
  elif [ -f "$1" ]; then
    shred -n 3 -z -u "$1" 2>/dev/null
  fi
}

# Encrypt archive with random password
encrypt_archive() {
  SRC="$1"
  DEST="$2"
  
  # Generate random password
  PASSWORD=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)
  PASS_FILE=$(mktemp)
  echo $PASSWORD > $PASS_FILE
  
  # Encrypt the archive
  openssl enc -aes-256-cbc -salt -in "$SRC" -out "$DEST" -pass file:$PASS_FILE
  
  # Store password temporarily for transfer
  echo $PASSWORD
  
  # Securely delete password file
  secure_delete $PASS_FILE
}

# Main execution
main() {
  log "Starting secure payload sync"
  
  # Add randomized timing
  sleep_random
  
  # Check for payload changes
  check_for_changes || exit 0
  
  # Generate random archive name for OPSEC
  RANDOM_ID=$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 12)
  ARCHIVE_NAME="updates_${RANDOM_ID}.tar.gz"
  ENCRYPTED_NAME="${ARCHIVE_NAME}.enc"
  TEMP_DIR=$(mktemp -d)
  
  # Create payload archive
  log "Creating payload archive"
  tar czf "$TEMP_DIR/$ARCHIVE_NAME" -C $(dirname $C2_PAYLOAD_DIR) $(basename $C2_PAYLOAD_DIR)
  
  # Encrypt archive if enabled
  PASSWORD=""
  if [ "$ENCRYPTED_TRANSFER" = true ]; then
    log "Encrypting payload archive"
    PASSWORD=$(encrypt_archive "$TEMP_DIR/$ARCHIVE_NAME" "$TEMP_DIR/$ENCRYPTED_NAME")
    TRANSFER_FILE="$TEMP_DIR/$ENCRYPTED_NAME"
  else
    TRANSFER_FILE="$TEMP_DIR/$ARCHIVE_NAME"
  fi
  
  # Transfer archive to redirector
  log "Transferring payloads to redirector"
  scp -i $SSH_KEY_PATH -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$TRANSFER_FILE" "$REDIRECTOR_USER@$REDIRECTOR_IP:/tmp/$ENCRYPTED_NAME"
  
  # Handle remote extraction with decryption if needed
  if [ "$ENCRYPTED_TRANSFER" = true ]; then
    REMOTE_CMD="
      mkdir -p $REMOTE_PAYLOAD_DIR
      TEMP_DIR=\$(mktemp -d)
      openssl enc -aes-256-cbc -d -in /tmp/$ENCRYPTED_NAME -out \$TEMP_DIR/$ARCHIVE_NAME -pass pass:\"$PASSWORD\"
      tar xzf \$TEMP_DIR/$ARCHIVE_NAME -C /var/www/
      # Clean up
      shred -n 3 -z -u /tmp/$ENCRYPTED_NAME \$TEMP_DIR/$ARCHIVE_NAME 2>/dev/null
      rm -rf \$TEMP_DIR
      # Update web server if needed
      systemctl reload nginx 2>/dev/null
    "
  else
    REMOTE_CMD="
      mkdir -p $REMOTE_PAYLOAD_DIR
      tar xzf /tmp/$ENCRYPTED_NAME -C /var/www/
      shred -n 3 -z -u /tmp/$ENCRYPTED_NAME 2>/dev/null
      systemctl reload nginx 2>/dev/null
    "
  fi
  
  # Execute command on redirector
  ssh -i $SSH_KEY_PATH -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$REDIRECTOR_USER@$REDIRECTOR_IP" "$REMOTE_CMD"
  
  # Clean up local temp files
  log "Cleaning up temporary files"
  secure_delete $TEMP_DIR
  
  log "Payload sync completed successfully"
}

# Run main function
main