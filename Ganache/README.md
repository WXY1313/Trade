


# Pre-requisites

* `Golang`  https://go.dev/dl/   

* `Solidity`  https://docs.soliditylang.org/en/v0.8.2/installing-solidity.html  Version: 0.8.20

* `Solidity compiler (solc)`  https://docs.soliditylang.org/en/latest/installing-solidity.html  
Version: 0.8.25-develop

* `Ganache-cli`  https://www.npmjs.com/package/ganache-cli
    
* `Abigen`    Version: v1.14.3
    ```bash
    go get -u github.com/ethereum/go-ethereum
    go install github.com/ethereum/go-ethereum/cmd/abigen@v1.14.3
    ```


# File description

* `main.go`   run this file to test the functionalities of the framework on Ganache.

* `../compile/contract/` stores the shared contract source and generated Go binding used by Ganache and Sepolia.

* `../compile/compile.sh` compiles Solidity and generates the shared Go contract binding.

* `genPrvKey.sh`  The script file generates accounts and stores in the`.env` file.
#########

# How to run

1. Generate private keys to generate the `.env` file in different Linux os or Mac os

    ```bash(Linux os)
    bash genPrvKey_Linux.sh
    ```

    ```bash(Mac os)
    bash genPrvKey_Mac.sh
    ```

2. start ganache

    ```bash
    ganache --mnemonic "Trade" -l 90071992547 -e 1000
    ```

3. Compile the shared smart contract code

    ```bash
    cd ../compile
    bash compile.sh
    cd ../Ganache
    ```

4. Run the main.go
    ```bash
    go run main.go
    ```
