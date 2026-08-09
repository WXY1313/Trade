# BSC Testnet

This module deploys the shared Trade smart contract and runs the same interaction flow on BNB Smart Chain Testnet.

## Network

- Network: BSC Testnet
- Chain ID: `97`
- Gas token: test BNB (`tBNB`)
- Explorer: `https://testnet.bscscan.com`
- Public RPC: `https://bsc-testnet-dataseed.bnbchain.org`

## Configuration

Set the following environment variables before running:

```bash
export BSC_TESTNET_RPC_URL="https://bsc-testnet-dataseed.bnbchain.org"
export BSC_TESTNET_WALLET_PASSWORD="your keystore password"
export BSC_TESTNET_WALLET_PATH="./wallet/deployer.json"
```

`BSC_TESTNET_WALLET_PATH` is optional and defaults to `./wallet/deployer.json`.
The wallet must contain enough tBNB to pay deployment and transaction fees.

To continue interacting with an already deployed contract instead of deploying a new one:

```bash
export BSC_TESTNET_CONTRACT_ADDRESS="0x..."
```

## Compile the shared contract

```bash
cd ../compile
bash compile.sh
cd "../BSC Testnet"
```

## Build and run

```bash
go build .
go run main.go
```
