# infura-sepolia
go连接以太网测试网上部署的智能合约
# Pre-requisites

* `Golang`  https://go.dev/dl/   

* `Solidity`  https://docs.soliditylang.org/en/v0.8.2/installing-solidity.html  Version: 0.8.20

* `Solidity compiler (solc)`  https://docs.soliditylang.org/en/latest/installing-solidity.html  
Version: 0.8.25-develop

* `infura` https://www.infura.io/ get API key-->choose endpoint(sepolia)-->copy link
    
* `Abigen`    Version: v1.14.3
    ```bash
    go get -u github.com/ethereum/go-ethereum
    go install github.com/ethereum/go-ethereum/cmd/abigen@v1.14.3
    ```
# File description

* `main.go`   run this file to interact with contract.

* `deploy/main.go`  run this file to deploy contract.

* `contract/`  The folder stores contract source code file (.sol) 

* `build/` The folder stores the abi file and bin file

* `contract/compile.sh`  The script file compiles solidity and generates go contract file.

* `gen/`  The folder stores generated go file which is imported in main.go

* `wallet` The folder stores two encrypted accounts 

# How to run

1. Generate the abi, bin file and go file

    ```bash
    cd contract
    bash compile.sh
    ```

2. Run the deploy/main.go

    ```bash
    cd deploy
    go run main.go
    ```

3. Edit main.go

    Replace the original address with your own contract address

4. Run the main.go
    ```bash
    go run main.go
    ```
