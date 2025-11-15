#!/bin/bash

echo "🔧 Setting up Zera Network Validator directories..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ENV_PATH="$SCRIPT_DIR/../.env"
CONFIG_PATH="$SCRIPT_DIR/../data/config/validator.conf"

# Create directories
mkdir -p $SCRIPT_DIR/../data
mkdir -p $SCRIPT_DIR/../data/config
mkdir -p $SCRIPT_DIR/../data/blockchain
mkdir -p $SCRIPT_DIR/../data/ccache
mkdir -p $SCRIPT_DIR/../data/logs
mkdir -p $SCRIPT_DIR/../data/reorgs
mkdir -p $SCRIPT_DIR/../data/copy

# Load environment variables from .env
if [ ! -f "$ENV_PATH" ]; then
  echo "❌ .env file not found at $ENV_PATH"
  exit 1
fi

set -o allexport
source "$ENV_PATH"
set +o allexport

# Generate the config file
cat <<EOF > "$CONFIG_PATH"
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
    echo "whitelist:$WHITELIST_ITEM" >> "$CONFIG_PATH"
  done
fi

# Only add dev_mode if it's set in the environment
if [ -n "$DEV_MODE" ]; then
  echo "dev_mode:$DEV_MODE" >> "$CONFIG_PATH"
fi

# Only add dev_mode if it's set in the environment
if [ -n "$BLOCK_HEIGHT" ]; then
  echo "block_height:$BLOCK_HEIGHT" >> "$CONFIG_PATH"
fi

# Only add api_port if it's set in the environment
if [ -n "$API_PORT" ]; then
  echo "api_port:$API_PORT" >> "$CONFIG_PATH"
fi

echo "✅ Config generated"
echo "✅ Directory setup complete."
echo "👉 You can now run: docker compose up"