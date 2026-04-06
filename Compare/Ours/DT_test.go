package DT

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"time"

	//"pvgss/crypto/dleq"

	"testing"

	"github.com/WXY1313/Trade/Crypto/CPABE/node"
	"github.com/WXY1313/Trade/Crypto/Operation"
	"github.com/WXY1313/Trade/Crypto/SymEnc"

	"github.com/fentec-project/bn256"
	// "github.com/stretchr/testify/assert"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Performance test
func TestDT(t *testing.T) {

	n := float64(500)

	//Setup Phase
	MPK, MSK, SPK, SSK := Setup()

	//Register  Phase
	//Seller computes own key pair (sko,pko)
	sko, _ := rand.Int(rand.Reader, bn256.Order)
	pko := new(bn256.G1).ScalarMult(MPK.H1, sko)
	vko := new(bn256.G2).ScalarMult(MPK.H2, sko)
	//Buyer computes own key pair (sku,pku)
	sku, _ := rand.Int(rand.Reader, bn256.Order)
	pku := new(bn256.G1).ScalarMult(MPK.G1, sku)
	vku := new(bn256.G2).ScalarMult(MPK.G2, sku)
	//KGC generates attribute key for the buyer
	var buyerAttrs []string
	for i := 1; i <= 20; i++ {
		buyerAttrs = append(buyerAttrs, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A100
	}
	AK := AKGen(MPK, MSK, buyerAttrs)

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

	//Generate and Check Ciphertext
	var CT *DTCiphertext
	starttime := time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		CT = Encrypt(MPK, SPK, root, s, pko)
	}
	endtime := time.Now().UnixMicro()
	fmt.Printf("Encrypt Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	var cipherVer bool
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		cipherVer = EncVer(MPK, SPK, CT, vko, path)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("EncVer Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	fmt.Printf("Ciphertext is %v\n", cipherVer)

	//Pay-per Phase
	//Seller computes re-encrypted key RK
	RK := ReKeyGen(MPK, CT, sko, pko, pku)
	//Check the validation of RK
	RKValid := ReKeyVer(MPK, CT, RK, vko, vku)
	fmt.Printf("The rekey is %v\n", RKValid)
	//Decrypt CT using pay-per buyer's RK and attribute key AK
	var recoverSymKey *bn256.GT
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		recoverSymKey = PerDecrypt(path, MPK, CT, RK, sku, AK)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("Pay-per Decrypt Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	if !Operation.GTEqual(SymKey, recoverSymKey) {
		t.Fatalf("decryption failed: SymKey mismatch\noriginal: %v\nrecovered: %v",
			SymKey, recoverSymKey)
	} else {
		Mes := SymEnc.XOREncryptDecrypt(ct, SymEnc.KDF(recoverSymKey))
		fmt.Printf("Message=%v\n", string(Mes))
	}

	//Subscribe Phase
	//Seller computes subscription key RK
	SK := SubKeyGen(SPK, SSK, pku)
	//Check the validation of RK
	SKValid := SubKeyVer(SPK, SK, vku)
	fmt.Printf("The subscription key is %v\n", SKValid)
	//Decrypt CT using subscription buyer's RK and attribute key AK
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		recoverSymKey = SubDecrypt(path, MPK, SPK, CT, matrix, SK, sku, AK)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("Subscribe Decrypt Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	if !Operation.GTEqual(SymKey, recoverSymKey) {
		t.Fatalf("decryption failed: SymKey mismatch\noriginal: %v\nrecovered: %v",
			SymKey, recoverSymKey)
	} else {
		Mes := SymEnc.XOREncryptDecrypt(ct, SymEnc.KDF(recoverSymKey))
		fmt.Printf("Message=%v\n", string(Mes))
	}

}
