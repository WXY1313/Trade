rm -rf ../build/*.bin
rm -rf ../build/*.abi
rm -rf ../gen/*.go
Name=DT
solc  --bin --abi $Name.sol -o ../build
abigen --bin ../build/$Name.bin --abi ../build/$Name.abi --pkg contract --out ../gen/$Name.go


