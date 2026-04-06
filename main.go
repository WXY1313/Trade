// used to interact with the smart contract
package main

import (
	Contract "PRE/gen"
	"context"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"

	//"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Q is the order of the integer field (Zq) that fits inside the snark
var Q, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

// R is the mod of the finite field
var R, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

func main() {
	// 1. Load encrypted wallet-file
	walletPath := "./wallet/UTC--2025-05-29T13-51-04.984946200Z--9dda53414c9a26b1054427718cd991ec14bd5fd4"
	walletData, err := os.ReadFile(walletPath)
	if err != nil {
		log.Fatalf("Read wallet-file fail: %v", err)
	}

	// 2. Decrypt wallet
	key, err := keystore.DecryptKey(walletData, "password")
	if err != nil {
		log.Fatalf("Decrypt wallet fail: %v", err)
	}

	// 3. Link Sepolia network
	client, err := ethclient.Dial("https://sepolia.infura.io/v3/de28dcce3b8f4d319a904bfab58d1e1a")
	if err != nil {
		log.Fatalf("Fail to link Sepolia nodes: %v", err)
	}
	defer client.Close()

	// 4. Obtain chain-ID and gas price
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatalf("Fail to obtain network-ID: %v", err)
	}

	// 5. Build contract instance
	contractAddress := common.HexToAddress("0x198c4e01792E3975F6d332381AA03f7CC97740AB")
	contract, err := Contract.NewContract(contractAddress, client)
	fmt.Printf("Contract=%v\n", contract)
	if err != nil {
		log.Fatalf("Fail to build contract instance: %v", err)
	}

	// 6. prepare transaction options
	auth, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, chainID)
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}

	// set gas parameters
	auth.GasLimit = 300000000
	auth.Context = context.Background()

	//==========================================System Initialization===========================================//
	// // the number of key shares
	// numShares := 50
	// // threshold value
	// //threshold := 2
	// threshold := numShares/2 + 1
	// n := 100

	// fmt.Printf("The number of shares is %v\n", numShares)
	// fmt.Printf("The threshold value is %v\n", threshold)

	// //Setup Algorithm(off-chain)
	// PK, _ := KZG.NewTrustedSetup(numShares)
	// //fmt.Printf("The system public key is %v\n",PK)
	// PKTau1 := make([]Contract.VerificationG1Point, numShares)
	// PKTau2 := make([]Contract.VerificationG2Point, numShares)
	// //PKG2i := make([]contract.VerificationG2Point, numShares)
	// for i := 0; i < numShares; i++ {
	// 	PKTau1[i] = Convert.G1ToG1Point(PK.Tau1[i])
	// 	PKTau2[i] = Convert.G2ToG2Point(PK.Tau2[i])
	// }

	// code, err := client.CodeAt(context.Background(), contractAddress, nil)
	// if err != nil {
	// 	log.Fatal("Fail to obtain contract code：", err)
	// }
	// if len(code) == 0 {
	// 	log.Fatalf("Fail to deploy contract code", contractAddress.Hex())
	// }

	// //Send UploadSystemKey transaction
	// auth1, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, chainID)
	// if err != nil {
	// 	log.Fatalf("Fail to build transaction signature: %v", err)
	// }
	// //invoke function
	// tx1, err := contract.UploadSystemKey(auth1, PKTau1, PKTau2)
	// if err != nil {
	// 	log.Fatalf("Fail to invoke UploadSystemKey: %v", err)
	// }
	// //wait for the transaction to succeed
	// receipt1, err := bind.WaitMined(context.Background(), client, tx1)
	// if err != nil {
	// 	log.Fatalf("Fail to ensure transaction: %v", err)
	// }
	// if receipt1.Status == 0 {
	// 	log.Fatal("Fial to excute transaction")
	// }
	// fmt.Printf("UploadSystemKey Gas used: %d\n", receipt1.GasUsed)
}
