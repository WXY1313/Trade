// used to interact with the smart contract
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"

	DT "github.com/WXY1313/Trade/Compare/Ours"
	"github.com/WXY1313/Trade/Crypto/CPABE/node"
	"github.com/WXY1313/Trade/Crypto/Operation"
	"github.com/WXY1313/Trade/Crypto/SymEnc"
	Contract "github.com/WXY1313/Trade/gen"
	"github.com/fentec-project/bn256"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

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
	contractAddress := common.HexToAddress("0xFe0983464b4DBb79Ec9334317448d25A78E6aD11")
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
	//auth.GasLimit = 16777216
	auth.Context = context.Background()

	//==========================================System Initialization===========================================//
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

	code, err := client.CodeAt(context.Background(), contractAddress, nil)
	if err != nil {
		log.Fatal("Fail to obtain contract code：", err)
	}
	if len(code) == 0 {
		log.Fatalf("Fail to deploy contract code", contractAddress.Hex())
	}

	//KGC Sends UploadMPK transaction
	auth1, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, chainID)
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx1, err := contract.UploadMPK(auth1, Operation.G1ToG1Point(MPK.G1), Operation.G2ToG2Point(MPK.G2), Operation.G1ToG1Point(MPK.U1), Operation.G2ToG2Point(MPK.U2), Operation.G1ToG1Point(MPK.H1), Operation.G2ToG2Point(MPK.H2), Operation.G1ToG1Point(MPK.AlphaG1), attrHxs, hxsG1, hxsG2)
	if err != nil {
		log.Fatalf("Fail to invoke UploadMPK: %v", err)
	}
	receipt1, err := bind.WaitMined(context.Background(), client, tx1)
	if err != nil {
		log.Fatalf("Fail to ensure transaction: %v", err)
	}
	if receipt1.Status == 0 {
		log.Fatal("Fial to excute transaction")
	}
	fmt.Printf("🌳 UploadMPK Gas used: %d\n", receipt1.GasUsed)

	//Seller uploads the master key pair SPK
	auth2, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, chainID)
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx2, err := contract.UploadSPK(auth2, Operation.G1ToG1Point(SPK.GammaG1))
	if err != nil {
		log.Fatalf("Fail to invoke UploadSystemKey: %v", err)
	}
	receipt2, err := bind.WaitMined(context.Background(), client, tx2)
	if err != nil {
		log.Fatalf("Fail to ensure transaction: %v", err)
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
	auth3, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, chainID)
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx3, err := contract.UploadPK(auth3, Operation.G1ToG1Point(pko), Operation.G2ToG2Point(vko), Operation.G1ToG1Point(pku), Operation.G2ToG2Point(vku))
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

	//Construct the buying policy
	//Access Policy
	nx := 1
	tx := (nx + 1) / 2
	root := node.NewNode(false, 3, 2, big.NewInt(int64(0)), "")
	P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr1")
	P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr2")
	P_1 := node.NewNode(false, nx, tx, big.NewInt(int64(3)), "")
	root.Children = []*node.Node{P_A, P_B, P_1}
	for i := 0; i < nx; i++ {
		P_1.Children = append(P_1.Children, node.NewNode(true, 0, 1, big.NewInt(int64(i+1)), "Attr"+strconv.Itoa(i+3)))
	}
	matrix, _ := node.Convert(root)
	//Authorized path
	path := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	Path_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr1")
	Path_1 := node.NewNode(false, tx, tx, big.NewInt(int64(3)), "")
	Path_1.Children = P_1.Children[:tx]
	path.Children = []*node.Node{Path_A, Path_1}
	CT := DT.Encrypt(MPK, SPK, root, s, pko)

	//Convert ABE Ciphertext
	abeNodes := Operation.ConvertTreeToInputs(root)
	var abeC1 []Contract.TradeG1Point
	var abeC2 []Contract.TradeG1Point
	var abeC3 []Contract.TradeG1Point
	var abeAttr [][32]byte
	for _, at := range node.RowToAttrib(root) {
		abeAttr = append(abeAttr, crypto.Keccak256Hash([]byte(at)))
		abeC1 = append(abeC1, Operation.G1ToG1Point(CT.C1.C1[at]))
		abeC2 = append(abeC2, Operation.G1ToG1Point(CT.C1.C2[at]))
		abeC3 = append(abeC3, Operation.G1ToG1Point(CT.C1.C3[at]))
	}

	auth4, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, chainID)
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx4, err := contract.UploadABECipher(auth4, Operation.G1ToG1Point(CT.Com), abeNodes,
		Operation.G1ToG1Point(CT.C1.Com), Operation.G1ToG1Point(CT.C1.C), Operation.G2ToG2Point(CT.C1.C_),
		abeAttr, abeC1, abeC2, abeC3)
	if err != nil {
		log.Fatalf("Fail to invoke UploadABECipher: %v", err)
	}
	receipt4, err := bind.WaitMined(context.Background(), client, tx4)
	if err != nil {
		log.Fatalf("Fail to ensure transaction: %v", err)
	}
	if receipt4.Status == 0 {
		log.Fatal("Fial to excute transaction")
	}
	fmt.Printf("🌳 UploadABECipher Gas used: %d\n", receipt4.GasUsed)

	auth5, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, chainID)
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx5, err := contract.UploadPayCipher(auth5, Operation.G1ToG1Point(CT.C2), Operation.G1ToG1Point(CT.C2Com),
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

	//Ciphetext Check
	cipherVer := DT.EncVer(MPK, SPK, CT, vko, path)
	fmt.Printf("Ciphertext is %v\n", cipherVer)

	//Pay-per Phase
	//Seller computes re-encrypted key RK
	RK := DT.ReKeyGen(MPK, CT, sko, pko, pku)
	fmt.Printf("Offchain ReKey=%v\n", RK)
	fmt.Printf("RK1=%v\n", Operation.G1ToG1Point(RK.D1))
	fmt.Printf("RK2=%v\n", Operation.G1ToG1Point(RK.D2))
	//Check the validation of RK
	auth6, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, chainID)
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx6, err := contract.ReKeyVer(auth6, Operation.G1ToG1Point(RK.D1), Operation.G1ToG1Point(RK.D2))
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
	verRK, _ := contract.GetRKResult(&bind.CallOpts{})
	fmt.Printf("The Verification results of ReKey is %v\n", verRK)

	//Decrypt CT using pay-per buyer's RK and attribute key AK
	recoverSymKey := DT.PerDecrypt(path, MPK, CT, RK, sku, AK)
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
	auth7, err := bind.NewKeyedTransactorWithChainID(key.PrivateKey, chainID)
	if err != nil {
		log.Fatalf("Fail to build transaction signature: %v", err)
	}
	tx7, err := contract.SubKeyVer(auth7, Operation.G1ToG1Point(SK.SK1), Operation.G1ToG1Point(SK.SK2))
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
	verSK, _ := contract.GetRKResult(&bind.CallOpts{})
	fmt.Printf("The Verification results of SubKey is %v\n", verSK)
	//Decrypt CT using subscription buyer's RK and attribute key AK
	recoverSymKey = DT.SubDecrypt(path, MPK, SPK, CT, matrix, SK, sku, AK)

	if !Operation.GTEqual(SymKey, recoverSymKey) {
		fmt.Printf("decryption failed: SymKey mismatch\noriginal: %v\nrecovered: %v", SymKey, recoverSymKey)
	} else {
		Mes := SymEnc.XOREncryptDecrypt(ct, SymEnc.KDF(recoverSymKey))
		fmt.Printf("Message=%v\n", string(Mes))
	}
}
