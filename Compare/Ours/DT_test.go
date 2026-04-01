package DT

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"

	//"pvgss/crypto/dleq"

	"testing"

	"github.com/WXY1313/Trade/Crypto/CPABE/Threshold/node"
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
	for i := 1; i <= 5; i++ {
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
	root := node.NewNode(false, 3, 3, big.NewInt(int64(0)), "")
	P_1 := node.NewNode(false, 3, 2, big.NewInt(int64(1)), "")
	P_D := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr1")
	P_2 := node.NewNode(false, 3, 1, big.NewInt(int64(3)), "")
	root.Children = []*node.Node{P_1, P_D, P_2}
	P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr2")
	P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr3")
	P_C := node.NewNode(true, 0, 1, big.NewInt(int64(3)), "Attr4")
	P_1.Children = []*node.Node{P_A, P_B, P_C}
	P_E := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr5")
	P_F := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr6")
	P_G := node.NewNode(true, 0, 1, big.NewInt(int64(3)), "Attr7")
	P_2.Children = []*node.Node{P_E, P_F, P_G}
	matrix, _ := node.Convert(root)

	//Authorized path
	path := node.NewNode(false, 3, 3, big.NewInt(int64(0)), "")
	P_1 = node.NewNode(false, 2, 2, big.NewInt(int64(1)), "")
	P_D = node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr1")
	P_2 = node.NewNode(false, 1, 1, big.NewInt(int64(3)), "")
	path.Children = []*node.Node{P_1, P_D, P_2}
	P_A = node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr2")
	P_B = node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr3")
	P_1.Children = []*node.Node{P_A, P_B}
	P_E = node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr5")
	P_2.Children = []*node.Node{P_E}

	//Generate and Check Ciphertext
	CT := Encrypt(MPK, SPK, root, s, pko)
	cipherVer := EncVer(MPK, SPK, CT, vko, path)
	fmt.Printf("Ciphertext is %v\n", cipherVer)

	//Pay-per Phase
	//Seller computes re-encrypted key RK
	RK := ReKeyGen(MPK, CT, sko, pko, pku)
	//Check the validation of RK
	RKValid := ReKeyVer(MPK, CT, RK, vko, vku)
	fmt.Printf("The rekey is %v\n", RKValid)
	//Decrypt CT using pay-per buyer's RK and attribute key AK
	recoverSymKey := PerDecrypt(path, MPK, CT, RK, sku, AK)
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
	recoverSymKey = SubDecrypt(path, MPK, SPK, CT, matrix, SK, sku, AK)
	if !Operation.GTEqual(SymKey, recoverSymKey) {
		t.Fatalf("decryption failed: SymKey mismatch\noriginal: %v\nrecovered: %v",
			SymKey, recoverSymKey)
	} else {
		Mes := SymEnc.XOREncryptDecrypt(ct, SymEnc.KDF(recoverSymKey))
		fmt.Printf("Message=%v\n", string(Mes))
	}

}
