package DT

import (
	"crypto/rand"
	"fmt"
	"strconv"

	//"pvgss/crypto/dleq"

	"testing"

	"github.com/WXY1313/Trade/Crypto/CPABE"
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
	policy := CPABE.GeneratePolicy(5)
	//Generate and Check Ciphertext
	CT, matrix := Encrypt(MPK, SPK, policy, s, pko)
	cipherVer := EncVer(MPK, SPK, CT, matrix, pko)
	fmt.Printf("Ciphertext is %v\n", cipherVer)

	//Pay-per Phase
	//Seller computes re-encrypted key RK
	RK := ReKeyGen(MPK, CT, sko, pko, pku)
	//Check the validation of RK
	RKValid := ReKeyVer(MPK, CT, RK, vko, vku)
	fmt.Printf("The rekey is %v\n", RKValid)
	//Decrypt CT using pay-per buyer's RK and attribute key AK
	recoverSymKey := PerDecrypt(MPK, CT, matrix, RK, sku, AK)
	if !CPABE.GTEqual(SymKey, recoverSymKey) {
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
	recoverSymKey = SubDecrypt(MPK, SPK, CT, matrix, SK, sku, AK)
	if !CPABE.GTEqual(SymKey, recoverSymKey) {
		t.Fatalf("decryption failed: SymKey mismatch\noriginal: %v\nrecovered: %v",
			SymKey, recoverSymKey)
	} else {
		Mes := SymEnc.XOREncryptDecrypt(ct, SymEnc.KDF(recoverSymKey))
		fmt.Printf("Message=%v\n", string(Mes))
	}

}
