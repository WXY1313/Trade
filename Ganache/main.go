// used to interact with the smart contract
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"strconv"

	"Ganache/utils"
	DT "Trade/Compare/Ours"
	"Trade/Crypto/CPABE/lsss"
	"Trade/Crypto/CPABE/node"
	"Trade/Crypto/Operation"
	"Trade/Crypto/SymEnc"
	"Trade/compile/contract"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	//Deploy the smart contract
	contract_name := "Trade"
	client, err := ethclient.Dial("http://127.0.0.1:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	privatekey := utils.GetENV("PRIVATE_KEY_1")

	auth := utils.Transact(client, privatekey, big.NewInt(0))

	// 打印账户余额
	fromAddress := auth.From
	balance, err := client.BalanceAt(context.Background(), fromAddress, nil)
	fmt.Printf("Deploy account balance: %s wei\n", balance.String())

	address, tx := utils.Deploy(client, contract_name, auth)
	receipt, err := bind.WaitMined(context.Background(), client, tx)
	if err != nil {
		log.Fatalf("Tx receipt failed: %v", err)
	}
	fmt.Printf("Deploy Gas used: %d\n", receipt.GasUsed)

	Contract, err := contract.NewContract(common.HexToAddress(address.Hex()), client)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%v\n", Contract)

	//======================================System Initialization=====================================//
	//Setup Phase
	MPK, MSK, SPK, SSK := DT.Setup()

	var hxsG1 []contract.TradeG1Point
	var hxsG2 []contract.TradeG2Point
	var attrHxs [][32]byte
	for at, value := range MPK.HXsG1 {
		attrHxs = append(attrHxs, crypto.Keccak256Hash([]byte(at)))
		hxsG1 = append(hxsG1, Operation.G1ToG1Point(value))
		hxsG2 = append(hxsG2, Operation.G2ToG2Point(MPK.HXsG2[at]))
	}

	//KGC Sends UploadMPK transaction
	auth1 := utils.Transact(client, privatekey, big.NewInt(0))
	tx1, err := Contract.UploadMPK(auth1, Operation.G1ToG1Point(MPK.G1), Operation.G2ToG2Point(MPK.G2),
		Operation.G1ToG1Point(MPK.U1), Operation.G2ToG2Point(MPK.U2), Operation.G1ToG1Point(MPK.H1),
		Operation.G2ToG2Point(MPK.H2), Operation.G1ToG1Point(MPK.AlphaG1), attrHxs, hxsG1, hxsG2)
	receipt1, err := bind.WaitMined(context.Background(), client, tx1)
	if receipt1.Status == 0 {
		log.Fatal("Fial to excute transaction")
	}
	fmt.Printf("🌳 UploadMPK Gas used: %d\n", receipt1.GasUsed)

	//Seller uploads the master key pair SPK
	auth2 := utils.Transact(client, privatekey, big.NewInt(0))
	tx2, err := Contract.UploadSPK(auth2, Operation.G1ToG1Point(SPK.GammaG1))
	receipt2, err := bind.WaitMined(context.Background(), client, tx2)
	if receipt2.Status == 0 {
		log.Fatal("Fial to excute transaction")
	}
	fmt.Printf("🌳 UploadSPK Gas used: %d\n", receipt2.GasUsed)

	//Register  Phase
	//Seller computes own key pair (sko,pko)
	sko, _ := rand.Int(rand.Reader, bn256.Order)
	pko := new(bn256.G1).ScalarMult(MPK.H1, sko)
	vko := new(bn256.G2).ScalarMult(MPK.H2, sko)
	//Buyer computes own key pair (sku,pku)
	sku, _ := rand.Int(rand.Reader, bn256.Order)
	pku := new(bn256.G1).ScalarMult(MPK.G1, sku)
	vku := new(bn256.G2).ScalarMult(MPK.G2, sku)
	//Seller and buyer sends their public key respectively
	auth3 := utils.Transact(client, privatekey, big.NewInt(0))
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx3, err := Contract.UploadPK(auth3, Operation.G1ToG1Point(pko), Operation.G2ToG2Point(vko), Operation.G1ToG1Point(pku), Operation.G2ToG2Point(vku))
	if err != nil {
		log.Fatalf("Fail to invoke UploadPK: %v", err)
	}
	receipt3, err := bind.WaitMined(context.Background(), client, tx3)
	if err != nil {
		log.Fatalf("Fail to ensure transaction: %v", err)
	}
	if receipt3.Status == 0 {
		log.Fatal("Fial to excute transaction")
	}
	fmt.Printf("🌳 UploadPK Gas used: %d\n", receipt3.GasUsed)
	//KGC generates attribute key for the buyer
	var buyerAttrs []string
	for i := 1; i <= 20; i++ {
		buyerAttrs = append(buyerAttrs, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A100
	}
	AK := DT.AKGen(MPK, MSK, buyerAttrs)

	//Encrypt Phase
	Message := "Secret"
	s, _ := rand.Int(rand.Reader, bn256.Order)
	SymKey := new(bn256.GT).ScalarMult(bn256.Pair(MPK.H1, MPK.U2), s)
	// Hide the trading message Message as the ciphertext ct using a symmetric key SymKey
	ct := SymEnc.XOREncryptDecrypt([]byte(Message), SymEnc.KDF(SymKey))

	//ABE Access Policy
	nx := 1
	ntx := (nx + 1) / 2
	abeRoot := node.NewNode(false, 3, 2, big.NewInt(0), "")
	P_A := node.NewNode(true, 0, 1, big.NewInt(1), "Attr1")
	P_B := node.NewNode(true, 0, 1, big.NewInt(2), "Attr2")
	P_1 := node.NewNode(false, nx, ntx, big.NewInt(3), "")
	abeRoot.Children = []*node.Node{P_A, P_B, P_1}
	for i := 0; i < nx; i++ {
		attrName := "Attr" + strconv.Itoa(i+3)
		leaf := node.NewNode(true, 0, 1, big.NewInt(int64(i+4)), attrName)
		P_1.Children = append(P_1.Children, leaf)
	}
	matrix, _ := node.Convert(abeRoot)
	abePolicy := node.ConvertTreeToInputs(abeRoot)
	CT := DT.Encrypt(MPK, SPK, abeRoot, s, pko)
	//Authorized path
	abePath := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	Path_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr1")
	Path_1 := node.NewNode(false, ntx, ntx, big.NewInt(int64(3)), "")
	Path_1.Children = P_1.Children[:ntx]
	abePath.Children = []*node.Node{Path_A, Path_1}
	attrSet := node.RowToAttrib(abePath)
	abeQ := make(map[string]*bn256.G1)
	for _, at := range attrSet {
		abeQ[at] = CT.C1.C3[at]
	}
	abeW, abe_RowMap, _ := lsss.Convert(abeRoot, abeQ)
	abeRowMap := node.ConvertNodesToNodeInputs(abe_RowMap)

	//Convert ABE Ciphertext
	var abeC1 []contract.TradeG1Point
	var abeC2 []contract.TradeG1Point
	var abeC3 []contract.TradeG1Point
	var abeAttr [][32]byte
	for _, at := range node.RowToAttrib(abeRoot) {
		abeAttr = append(abeAttr, crypto.Keccak256Hash([]byte(at)))
		abeC1 = append(abeC1, Operation.G1ToG1Point(CT.C1.C1[at]))
		abeC2 = append(abeC2, Operation.G1ToG1Point(CT.C1.C2[at]))
		abeC3 = append(abeC3, Operation.G1ToG1Point(CT.C1.C3[at]))
	}
	var abePathAttr [][32]byte
	for _, at := range node.RowToAttrib(abePath) {
		abePathAttr = append(abePathAttr, crypto.Keccak256Hash([]byte(at)))
	}

	//===========================================================================================//
	//Ciphetext Check
	tradePolicy := node.ConvertTreeToInputs(CT.Policy)
	tradeQ := make(map[string]*bn256.G1)
	var tradePathAttr [][32]byte
	tradePathAttr = append(tradePathAttr, crypto.Keccak256Hash([]byte("buy")))
	tradePathAttr = append(tradePathAttr, crypto.Keccak256Hash([]byte("per")))
	tradeQ["buy"] = CT.C1.Com
	tradeQ["per"] = CT.C2Com
	tradeW, _, _ := lsss.Convert(CT.Policy, tradeQ)
	auth4 := utils.Transact(client, privatekey, big.NewInt(0))
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx4, err := Contract.UploadABECipher(auth4, abeW, abeRowMap, abePathAttr, abePolicy,
		Operation.G1ToG1Point(CT.C1.Com), Operation.G1ToG1Point(CT.C1.C), Operation.G2ToG2Point(CT.C1.C_),
		abeC1, abeC2, abeC3)
	if err != nil {
		log.Fatalf("Fail to invoke ABECipherCheck: %v", err)
	}
	receipt4, err := bind.WaitMined(context.Background(), client, tx4)
	if err != nil {
		log.Fatalf("Fail to ensure transaction: %v", err)
	}
	if receipt4.Status == 0 {
		log.Fatal("Fial to excute transaction")
	}
	fmt.Printf("🌳 ABECipherCheck Gas used: %d\n", receipt4.GasUsed)
	verABE, _ := Contract.GetABEResult(&bind.CallOpts{})
	fmt.Printf("The ABE Ciphertext is %v\n", verABE)

	auth5 := utils.Transact(client, privatekey, big.NewInt(0))
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx5, err := Contract.UploadPayCipher(auth5, tradePolicy, tradeW, Operation.G1ToG1Point(CT.Com), Operation.G1ToG1Point(CT.C2), Operation.G1ToG1Point(CT.C2Com),
		Operation.G1ToG1Point(CT.C3.Com), Operation.G1ToG1Point(CT.C3.C1), Operation.G2ToG2Point(CT.C3.C2))
	if err != nil {
		log.Fatalf("Fail to invoke UploadPayCipher: %v", err)
	}
	receipt5, err := bind.WaitMined(context.Background(), client, tx5)
	if err != nil {
		log.Fatalf("Fail to ensure transaction: %v", err)
	}
	if receipt5.Status == 0 {
		log.Fatal("Fial to excute transaction")
	}
	fmt.Printf("🌳 UploadPayCipher Gas used: %d\n", receipt5.GasUsed)
	verPay, _ := Contract.GetPayResult(&bind.CallOpts{})
	fmt.Printf("The Pay Ciphertext is %v\n", verPay)

	//Pay-per Phase
	//Seller computes re-encrypted key RK
	RK := DT.ReKeyGen(MPK, CT, sko, pko, pku)
	//Check the validation of RK
	auth6 := utils.Transact(client, privatekey, big.NewInt(0))
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx6, err := Contract.ReKeyVer(auth6, Operation.G1ToG1Point(RK.D1), Operation.G1ToG1Point(RK.D2))
	if err != nil {
		log.Fatalf("Fail to invoke ReKeyVer: %v", err)
	}
	receipt6, err := bind.WaitMined(context.Background(), client, tx6)
	if err != nil {
		log.Fatalf("Fail to ensure transaction: %v", err)
	}
	if receipt6.Status == 0 {
		log.Fatal("Fial to excute transaction")
	}
	fmt.Printf("🌳 ReKeyVer Gas used: %d\n", receipt6.GasUsed)
	verRK, _ := Contract.GetRKResult(&bind.CallOpts{})
	fmt.Printf("The Verification results of ReKey is %v\n", verRK)

	//Decrypt CT using pay-per buyer's RK and attribute key AK
	recoverSymKey := DT.PerDecrypt(abePath, MPK, CT, RK, sku, AK)
	if !Operation.GTEqual(SymKey, recoverSymKey) {
		fmt.Printf("decryption failed: SymKey mismatch\noriginal: %v\nrecovered: %v", SymKey, recoverSymKey)
	} else {
		Mes := SymEnc.XOREncryptDecrypt(ct, SymEnc.KDF(recoverSymKey))
		fmt.Printf("Message=%v\n", string(Mes))
	}

	//Subscribe Phase
	//Seller computes subscription key RK
	SK := DT.SubKeyGen(SPK, SSK, pku)
	//Check the validation of RK
	auth7 := utils.Transact(client, privatekey, big.NewInt(0))
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx7, err := Contract.SubKeyVer(auth7, Operation.G1ToG1Point(SK.SK1), Operation.G1ToG1Point(SK.SK2))
	if err != nil {
		log.Fatalf("Fail to invoke SubKeyVer: %v", err)
	}
	receipt7, err := bind.WaitMined(context.Background(), client, tx7)
	if err != nil {
		log.Fatalf("Fail to ensure transaction: %v", err)
	}
	if receipt6.Status == 0 {
		log.Fatal("Fial to excute transaction")
	}
	fmt.Printf("🌳 SubKeyVer Gas used: %d\n", receipt7.GasUsed)
	verSK, _ := Contract.GetSKResult(&bind.CallOpts{})
	fmt.Printf("The Verification results of SubKey is %v\n", verSK)
	//Decrypt CT using subscription buyer's RK and attribute key AK
	recoverSymKey = DT.SubDecrypt(abePath, MPK, SPK, CT, matrix, SK, sku, AK)

	if !Operation.GTEqual(SymKey, recoverSymKey) {
		fmt.Printf("decryption failed: SymKey mismatch\noriginal: %v\nrecovered: %v", SymKey, recoverSymKey)
	} else {
		Mes := SymEnc.XOREncryptDecrypt(ct, SymEnc.KDF(recoverSymKey))
		fmt.Printf("Message=%v\n", string(Mes))
	}
}
