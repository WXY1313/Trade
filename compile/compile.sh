rm -rf ./contract/*.bin
rm -rf ./contract/*.abi
rm -rf ./contract/*.go
Name=Trade
solc --evm-version paris --optimize --via-ir --abi ./contract/$Name.sol -o contract --overwrite
solc --evm-version paris --optimize --via-ir --bin ./contract/$Name.sol -o contract --overwrite
abigen --abi=./contract/$Name.abi --bin=./contract/$Name.bin --pkg=contract --out=./contract/$Name.go
