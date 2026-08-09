// used to interact with the smart contract
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"

	DT "Trade/Compare/Ours"
	"Trade/Crypto/CPABE/lsss"
	"Trade/Crypto/CPABE/node"
	"Trade/Crypto/Operation"
	"Trade/Crypto/SymEnc"
	Contract "Trade/compile/contract"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/ethereum/go-ethereum/ethclient"
)

const bscTestnetChainID = 97

func main() {
	ctx := context.Background()
	rpcURL := requiredEnv("BSC_TESTNET_RPC_URL")
	walletPassword := requiredEnv("BSC_TESTNET_WALLET_PASSWORD")
	walletPath := os.Getenv("BSC_TESTNET_WALLET_PATH")
	if walletPath == "" {
		walletPath = "./wallet/deployer.json"
	}

	walletData, err := os.ReadFile(walletPath)
	if err != nil {
		log.Fatalf("Read wallet file %q failed: %v", walletPath, err)
	}
	key, err := keystore.DecryptKey(walletData, walletPassword)
	if err != nil {
		log.Fatalf("Decrypt wallet failed: %v", err)
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		log.Fatalf("Connect to BSC Testnet RPC failed: %v", err)
	}
	defer client.Close()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		log.Fatalf("Obtain chain ID failed: %v", err)
	}
	if chainID.Cmp(big.NewInt(bscTestnetChainID)) != 0 {
		log.Fatalf("Refusing to deploy: RPC chain ID is %s, expected BSC Testnet (%d)", chainID, bscTestnetChainID)
	}

	deployer := crypto.PubkeyToAddress(key.PrivateKey.PublicKey)
	balance, err := client.BalanceAt(ctx, deployer, nil)
	if err != nil {
		log.Fatalf("Obtain deployer balance failed: %v", err)
	}
	fmt.Printf("BSC Testnet deployer: %s\n", deployer.Hex())
	fmt.Printf("BSC Testnet balance: %s wei\n", balance.String())
	if balance.Sign() == 0 {
		log.Fatal("BSC Testnet deployer has no test BNB; fund it before deployment")
	}

	var contractInstance *Contract.Contract
	contractAddress := os.Getenv("BSC_TESTNET_CONTRACT_ADDRESS")
	if contractAddress != "" {
		if !common.IsHexAddress(contractAddress) {
			log.Fatalf("Invalid BSC_TESTNET_CONTRACT_ADDRESS: %q", contractAddress)
		}
		contractInstance, err = Contract.NewContract(common.HexToAddress(contractAddress), client)
		if err != nil {
			log.Fatalf("Bind existing contract failed: %v", err)
		}
		fmt.Printf("Using existing BSC Testnet contract: %s\n", common.HexToAddress(contractAddress).Hex())
	} else {
		auth := newTransactor(key.PrivateKey, chainID, ctx)
		address, tx, deployedContract, deployErr := Contract.DeployContract(auth, client)
		if deployErr != nil {
			log.Fatalf("Submit contract deployment failed: %v", deployErr)
		}
		fmt.Printf("Deployment transaction: %s\n", tx.Hash().Hex())
		receipt, waitErr := bind.WaitMined(ctx, client, tx)
		if waitErr != nil {
			log.Fatalf("Wait for contract deployment failed: %v", waitErr)
		}
		if receipt.Status != 1 {
			log.Fatalf("Contract deployment reverted (tx %s)", tx.Hash().Hex())
		}
		fmt.Printf("Contract deployed on BSC Testnet: %s\n", address.Hex())
		fmt.Printf("Deploy Gas used: %d\n", receipt.GasUsed)
		contractInstance = deployedContract
	}

	fmt.Printf("Contract=%v\n", contractInstance)

	//======================================System Initialization=====================================//
	//Setup Phase
	MPK, MSK, SPK, SSK := DT.Setup()

	var hxsG1 []Contract.TradeG1Point
	var hxsG2 []Contract.TradeG2Point
	var attrHxs [][32]byte
	for at, value := range MPK.HXsG1 {
		attrHxs = append(attrHxs, crypto.Keccak256Hash([]byte(at)))
		hxsG1 = append(hxsG1, Operation.G1ToG1Point(value))
		hxsG2 = append(hxsG2, Operation.G2ToG2Point(MPK.HXsG2[at]))
	}

	//KGC Sends UploadMPK transaction
	auth1 := newTransactor(key.PrivateKey, chainID, ctx)
	tx1, err := contractInstance.UploadMPK(auth1, Operation.G1ToG1Point(MPK.G1), Operation.G2ToG2Point(MPK.G2),
		Operation.G1ToG1Point(MPK.U1), Operation.G2ToG2Point(MPK.U2), Operation.G1ToG1Point(MPK.H1),
		Operation.G2ToG2Point(MPK.H2), Operation.G1ToG1Point(MPK.AlphaG1), attrHxs, hxsG1, hxsG2)
	if err != nil {
		log.Fatalf("Fail to invoke UploadMPK: %v", err)
	}
	receipt1, err := bind.WaitMined(ctx, client, tx1)
	if err != nil {
		log.Fatalf("Fail to confirm UploadMPK: %v", err)
	}
	if receipt1.Status == 0 {
		log.Fatal("Fial to excute transaction")
	}
	fmt.Printf("🌳 UploadMPK Gas used: %d\n", receipt1.GasUsed)

	//Seller uploads the master key pair SPK
	auth2 := newTransactor(key.PrivateKey, chainID, ctx)
	tx2, err := contractInstance.UploadSPK(auth2, Operation.G1ToG1Point(SPK.GammaG1))
	if err != nil {
		log.Fatalf("Fail to invoke UploadSPK: %v", err)
	}
	receipt2, err := bind.WaitMined(ctx, client, tx2)
	if err != nil {
		log.Fatalf("Fail to confirm UploadSPK: %v", err)
	}
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
	auth3 := newTransactor(key.PrivateKey, chainID, ctx)
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx3, err := contractInstance.UploadPK(auth3, Operation.G1ToG1Point(pko), Operation.G2ToG2Point(vko), Operation.G1ToG1Point(pku), Operation.G2ToG2Point(vku))
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
	abeW, abeRowNodes, err := lsss.Convert(abeRoot, abeQ)
	if err != nil {
		log.Fatalf("Build ABE reconstruction data failed: %v", err)
	}
	abeRowMap := node.ConvertNodesToNodeInputs(abeRowNodes)

	//Convert ABE Ciphertext
	var abeC1 []Contract.TradeG1Point
	var abeC2 []Contract.TradeG1Point
	var abeC3 []Contract.TradeG1Point
	for _, at := range node.RowToAttrib(abeRoot) {
		abeC1 = append(abeC1, Operation.G1ToG1Point(CT.C1.C1[at]))
		abeC2 = append(abeC2, Operation.G1ToG1Point(CT.C1.C2[at]))
		abeC3 = append(abeC3, Operation.G1ToG1Point(CT.C1.C3[at]))
	}
	var abePathAttr [][32]byte
	for _, at := range node.RowToAttrib(abePath) {
		abePathAttr = append(abePathAttr, crypto.Keccak256Hash([]byte(at)))
	}

	tradePolicy := node.ConvertTreeToInputs(CT.Policy)
	tradeQ := map[string]*bn256.G1{
		"buy": CT.C1.Com,
		"per": CT.C2Com,
	}
	tradeW, tradeRowMap, err := lsss.Convert(CT.Policy, tradeQ)
	if err != nil {
		log.Fatalf("Build Trade-policy reconstruction data failed: %v", err)
	}

	//===========================================================================================//
	auth4 := newTransactor(key.PrivateKey, chainID, ctx)
	tx4, err := contractInstance.UploadABECipher(auth4, abeW, abeRowMap, abePathAttr, abePolicy,
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
	fmt.Printf("🌳 UploadABECipher Gas used: %d\n", receipt4.GasUsed)
	verABE, err := contractInstance.GetABEResult(&bind.CallOpts{Context: ctx})
	if err != nil {
		log.Fatalf("Read ABE verification result failed: %v", err)
	}
	fmt.Printf("The ABE Ciphertext is %v\n", verABE)

	auth5 := newTransactor(key.PrivateKey, chainID, ctx)
	tx5, err := contractInstance.UploadPayCipher(auth5, tradePolicy, tradeW, Operation.G1ToG1Point(CT.Com),
		Operation.G1ToG1Point(CT.C2), Operation.G1ToG1Point(CT.C2Com), Operation.G1ToG1Point(CT.C3.Com),
		Operation.G1ToG1Point(CT.C3.C1), Operation.G2ToG2Point(CT.C3.C2))
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
	verPay, err := contractInstance.GetPayResult(&bind.CallOpts{Context: ctx})
	if err != nil {
		log.Fatalf("Read Pay verification result failed: %v", err)
	}
	fmt.Printf("The Pay Ciphertext is %v\n", verPay)
	fmt.Printf("Ciphertext is %v\n", DT.EncVer(MPK, SPK, CT, vko, abePath, tradeW, tradeRowMap, tradeQ))

	//Pay-per Phase
	//Seller computes re-encrypted key RK
	RK := DT.ReKeyGen(MPK, CT, sko, pko, pku)
	//Check the validation of RK
	auth6 := newTransactor(key.PrivateKey, chainID, ctx)
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx6, err := contractInstance.ReKeyVer(auth6, Operation.G1ToG1Point(RK.D1), Operation.G1ToG1Point(RK.D2))
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
	verRK, _ := contractInstance.GetRKResult(&bind.CallOpts{})
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
	auth7 := newTransactor(key.PrivateKey, chainID, ctx)
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx7, err := contractInstance.SubKeyVer(auth7, Operation.G1ToG1Point(SK.SK1), Operation.G1ToG1Point(SK.SK2))
	if err != nil {
		log.Fatalf("Fail to invoke SubKeyVer: %v", err)
	}
	receipt7, err := bind.WaitMined(context.Background(), client, tx7)
	if err != nil {
		log.Fatalf("Fail to ensure transaction: %v", err)
	}
	if receipt7.Status == 0 {
		log.Fatal("Fial to excute transaction")
	}
	fmt.Printf("🌳 SubKeyVer Gas used: %d\n", receipt7.GasUsed)
	verSK, _ := contractInstance.GetSKResult(&bind.CallOpts{})
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

func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("Required environment variable %s is not set", name)
	}
	return value
}

func newTransactor(privateKey *ecdsa.PrivateKey, chainID *big.Int, ctx context.Context) *bind.TransactOpts {
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		log.Fatalf("Build transaction signer failed: %v", err)
	}
	auth.Context = ctx
	return auth
}
