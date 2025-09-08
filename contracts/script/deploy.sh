#!/bin/bash

# Simple deployment script for KeyManager contract

set -e

# Load environment variables if .env file exists
if [ -f ".env" ]; then
    echo "Loading environment from .env file..."
    # Use source to properly handle quoted values
    set -a
    source .env
    set +a
fi

# Check if required environment variables are set
if [ -z "$MANAGER_ADDRESS" ]; then
    echo "Error: MANAGER_ADDRESS is required"
    echo "Please set MANAGER_ADDRESS in your .env file"
    echo ""
    echo "Example .env file:"
    echo "MANAGER_ADDRESS=0x1234567890123456789012345678901234567890"
    echo "RPC_URL=http://localhost:8545"
    echo "MNEMONIC=\"your twelve word mnemonic phrase here\""
    echo "ACCOUNT_INDEX=0"
    exit 1
fi

# Use environment variables with defaults
RPC_URL=${RPC_URL:-"http://localhost:8545"}
ACCOUNT_INDEX=${ACCOUNT_INDEX:-0}
MNEMONIC=${MNEMONIC:-"test test test test test test test test test test test junk"}

echo "Deploying KeyManager contract..."
echo "Manager address: $MANAGER_ADDRESS"
echo "RPC URL: $RPC_URL"
echo "Account index: $ACCOUNT_INDEX"
echo

# Set environment variable for the script
export MANAGER_ADDRESS=$MANAGER_ADDRESS

# Build forge command
FORGE_CMD="forge script script/DeployKeyManager.s.sol:DeployKeyManager --rpc-url $RPC_URL --broadcast --mnemonics \"$MNEMONIC\" --mnemonic-indexes $ACCOUNT_INDEX"


echo "Executing Forge command"
echo

# Deploy the contract and capture output
DEPLOYMENT_OUTPUT=$(eval $FORGE_CMD 2>&1)
DEPLOYMENT_EXIT_CODE=$?

if [ $? -eq 124 ]; then
    echo "Forge command timed out - likely invalid flags or connection issue"
    exit 1
fi

echo "Forge command completed with exit code: $DEPLOYMENT_EXIT_CODE"

# Display the deployment output
echo "$DEPLOYMENT_OUTPUT"

# Check if deployment was successful
if [ $DEPLOYMENT_EXIT_CODE -eq 0 ]; then
    echo
    echo "Deployment complete!"
    echo "Check the output above for contract addresses."
    
    # Try to extract addresses from the output (optional enhancement)
    echo
    echo "Extracted contract addresses:"
    echo "$DEPLOYMENT_OUTPUT" | grep -E "(KeyManager implementation deployed at:|ERC1967Proxy deployed at:)" || echo "Could not extract addresses from output"
else
    echo
    echo "Deployment failed with exit code $DEPLOYMENT_EXIT_CODE"
    exit $DEPLOYMENT_EXIT_CODE
fi
