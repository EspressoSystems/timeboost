# Deploy KeyManager Contract

This script deploys the KeyManager contract to any Ethereum network.

## Quick Start

1. **Set up your environment:**
   ```bash
   cp env.example .env
   # Edit .env with your values
   ```

2. **Start a local blockchain (if testing locally):**
   ```bash
   anvil
   ```

3. **Deploy:**
   ```bash
   ./script/deploy.sh
   ```

That's it! The script will deploy your contract and show you the addresses.

## What You Need

- **Manager Address**: Who will manage the contract (usually a multisig wallet)
- **RPC URL**: Where to deploy (localhost for testing, or a real network)
- **Mnemonic**: Your wallet phrase (optional for local testing)

## How It Works

The script deploys two contracts:
1. **KeyManager** - The actual contract with your business logic
2. **Proxy** - Points to the KeyManager, so you can upgrade it later

The proxy gets initialized with your manager address, and that's it!

## Configuration

All settings go in your `.env` file:

```bash
# Required: Who manages the contract
MANAGER_ADDRESS=0x1234567890123456789012345678901234567890

# Optional: Where to deploy (defaults to localhost)
RPC_URL=http://localhost:8545

# Optional: Your wallet phrase (defaults to Anvil's test account)
MNEMONIC="your twelve word mnemonic phrase here"
ACCOUNT_INDEX=0
```

## How it works
The deployment script:
1. **Deploys** the KeyManager implementation contract
2. **Creates** an ERC1967 proxy pointing to the implementation
3. **Initializes** the proxy with your manager address
4. **Verifies** the deployment was successful
5. **Returns** both proxy and implementation addresses


## Troubleshooting

**"Manager address not set"**
- Make sure you have `MANAGER_ADDRESS=0x...` in your `.env` file

**"Deployment failed"**
- Check your RPC URL works
- Make sure your wallet has enough ETH for gas
- Verify your mnemonic is correct

**Need help?**
- Make sure Foundry is installed: `forge --version`
- Check your `.env` file has all required values
