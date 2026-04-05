package Sub

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/WXY1313/Trade/Crypto/CPABE"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/require"
)

func TestAll(t *testing.T) {
	//Setup
	mpk, _, _ := CPABE.Setup()
	spk, ssk, err := Setup(mpk)

	//Generate data user's key pair
	sampler := sample.NewUniformRange(big.NewInt(1), spk.Order)
	sk, _ := sampler.Sample()
	pk := new(bn256.G1).ScalarMult(spk.G1, sk)
	vk := new(bn256.G2).ScalarMult(spk.G2, sk)

	//KeyGen
	subkey, err := KeyGen(spk, ssk, pk)
	require.NoError(t, err)
	require.NotNil(t, subkey)

	//KeyCheck
	keyVer := KeyCheck(spk, subkey, vk)
	fmt.Printf("The subkey is %v\n", keyVer)

	//Encrypt
	m, _ := sampler.Sample()
	ct, err := Encrypt(spk, m)
	if err != nil {
		t.Errorf("fail to generate subscribe ciphertext")
		return
	}

	//CipherCheck
	cipherVer := CipherCheck(spk, ct)
	fmt.Printf("The Ciphertext is %v\n", cipherVer)

	// create new MAABE struct with Global Parameters

	//Decrypt
	recoverM, err := Decrypt(spk, ct, subkey, sk)
	if !GTEqual(ct.M, recoverM) {
		t.Fatalf("decryption failed: M mismatch\noriginal: %v\nrecovered: %v",
			ct.M, recoverM)
	}
}
