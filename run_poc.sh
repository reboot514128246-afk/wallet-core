#!/bin/bash

# Ensure Foundry is installed and forge is in PATH
# If forge is not in PATH, you might need to source ~/.bashrc or provide the full path

FORGE_BIN=$(which forge)
if [ -z "$FORGE_BIN" ]; then
    FORGE_BIN="$HOME/.foundry/bin/forge"
fi

if [ ! -f "$FORGE_BIN" ]; then
    echo "Error: forge not found. Please install Foundry or ensure it is in your PATH."
    exit 1
fi

echo "Running Privilege Escalation Bypass PoC..."
DEPLOY_FACTORY_SALT=0x0000000000000000000000000000000000000000000000000000000000000000 $FORGE_BIN test --mt test_bypass_onlySelf -vvv
