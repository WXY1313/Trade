// used to deploy contract
package main

import (
	hello "PRE/gen"
	"context"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	b, err := os.ReadFile("../wallet/UTC--2025-05-29T13-51-04.984946200Z--9dda53414c9a26b1054427718cd991ec14bd5fd4")
	if err != nil {
		log.Fatal(err)
	}
	key, err := keystore.DecryptKey(b, "password")
	if err != nil {
		log.Fatal(err)
	}

	var (
		//localurl  = "http://127.0.0.1:7545"
		infuralurl = "https://sepolia.infura.io/v3/de28dcce3b8f4d319a904bfab58d1e1a"
	)
	client, err := ethclient.DialContext(context.Background(), infuralurl)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	add := crypto.PubkeyToAddress(key.PrivateKey.PublicKey)
	nonce, err := client.PendingNonceAt(context.Background(), add)
	if err != nil {
		log.Fatal(err)
	}
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	chainId, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, chainId)
	if err != nil {
		log.Fatal(err)
	}
	auth.GasPrice = gasPrice
	auth.GasLimit = uint64(30000000)
	auth.Nonce = big.NewInt(int64(nonce))
	a, tx, _, err := hello.DeployContract(auth, client)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("------------------")
	//输出合约地址
	fmt.Println(a.Hex())
	//输出交易哈希
	fmt.Println(tx.Hash().Hex())
	fmt.Println("------------------")

	// 等待部署完成
	fmt.Println("等待合约部署上链中...")
	_, err = bind.WaitDeployed(context.Background(), client, tx)
	if err != nil {
		log.Fatal("合约部署确认失败:", err)
	}
	fmt.Println("合约成功部署并上链")
}
