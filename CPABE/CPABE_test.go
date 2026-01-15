package CPABE

import (
	"math/big"
	"strconv"
	"testing"

	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/require"
)

func TestAll(t *testing.T) {
	//Setup
	cpabe := NewCPABE()
	MPK, MSK, err := cpabe.Setup()

	//KeyGen
	var userAttrs []string
	for i := 1; i <= 10; i++ {
		userAttrs = append(userAttrs, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A100
	}
	//KeyGen
	SK, err := cpabe.KeyGen(MPK, MSK, userAttrs)
	require.NoError(t, err)
	require.NotNil(t, SK)

	//Encrypt
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	m, _ := sampler.Sample()
	policy := GeneratePolicy(10)
	ABECT, err := cpabe.Encrypt(MPK, m, policy)
	if err != nil {
		t.Errorf("fail to generate ABE ciphertext")
		return
	}

	//CipherCheck
	resultCipher, _ := cpabe.CipherCheck(MPK, ABECT)
	t.Logf("CipherCheck Result : %v", resultCipher)

	//Decrypt
	recoverMessage, err := cpabe.Decrypt(MPK, ABECT, SK)
	if !GTEqual(ABECT.Message, recoverMessage) {
		t.Fatalf("decryption failed: Kθ mismatch\noriginal: %v\nrecovered: %v",
			ABECT.Message, recoverMessage)
	}
}
