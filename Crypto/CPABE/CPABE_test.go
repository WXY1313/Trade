package CPABE

import (
	"fmt"
	"math/big"
	"strconv"
	"testing"

	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/require"
	"github.com/WXY1313/Trade/Crypto/Operation"
)

func TestAll(t *testing.T) {
	//Setup
	MPK, MSK, err := Setup()

	//KeyGen
	var userAttrs []string
	for i := 1; i <= 5; i++ {
		userAttrs = append(userAttrs, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A100
	}
	//KeyGen
	SK, err := KeyGen(MPK, MSK, userAttrs)
	require.NoError(t, err)
	require.NotNil(t, SK)

	//Encrypt
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	m, _ := sampler.Sample()
	policy := GeneratePolicy(5)
	ABECT, err := Encrypt(MPK, m, policy)
	if err != nil {
		t.Errorf("fail to generate ABE ciphertext")
		return
	}

	//CipherCheck
	resultCipher := CipherCheck(MPK, ABECT)
	fmt.Printf("CipherCheck Result : %v\n", resultCipher)

	// create new MAABE struct with Global Parameters

	//Decrypt
	recoverMessage, err := Decrypt(MPK, ABECT, SK)
	if !Operation.GTEqual(ABECT.Message, recoverMessage) {
		t.Fatalf("decryption failed: Kθ mismatch\noriginal: %v\nrecovered: %v",
			ABECT.Message, recoverMessage)
	}
}
