#!/bin/bash

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ENV_FILE="$SCRIPT_DIR/../.env"
DEST_CONFIG="$SCRIPT_DIR/../data/config/validator.conf"

echo "📁 Generating validator config from .env..."

# Check if .env file exists
if [ ! -f "$ENV_FILE" ]; then
  echo "❌ Error: .env file not found at $ENV_FILE"
  exit 1
fi

# Load .env values
set -o allexport
source "$ENV_FILE"
set +o allexport

# Ensure destination folder exists
mkdir -p "$(dirname "$DEST_CONFIG")"

# Generate the config file
cat <<EOF > "$DEST_CONFIG"
host:$HOST
client_port:$CLIENT_PORT
server_port:$SERVER_PORT
public_key:$PUBLIC_KEY
private_key:$PRIVATE_KEY
fee_wallet_address:$FEE_WALLET_ADDRESS
register:$REGISTER
seed_validator:$SEED_VALIDATOR
EOF


# Handle multiple whitelist entries
if [ -n "$WHITELIST" ]; then
  IFS=',' read -ra WHITELIST_ARRAY <<< "$WHITELIST"
  for WHITELIST_ITEM in "${WHITELIST_ARRAY[@]}"; do
    echo "whitelist:$WHITELIST_ITEM" >> "$DEST_CONFIG"
  done
fi

# Only add dev_mode if it's set in the environment
if [ -n "$DEV_MODE" ]; then
  echo "dev_mode:$DEV_MODE" >> "$DEST_CONFIG"
fi

# Only add dev_mode if it's set in the environment
if [ -n "$BLOCK_HEIGHT" ]; then
  echo "block_height:$BLOCK_HEIGHT" >> "$DEST_CONFIG"
fi

# Only add api_port if it's set in the environment
if [ -n "$API_PORT" ]; then
  echo "api_port:$API_PORT" >> "$DEST_CONFIG"
fi

echo "✅ Config generated successfully from .env."