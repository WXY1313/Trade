package FSAC

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAll(t *testing.T) {
	//Setup
	fsac := NewFSAC()
	MPK, MSK, err := fsac.Setup()

	//KeyGen
	var userAttrs []string
	for i := 1; i <= 5; i++ {
		userAttrs = append(userAttrs, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A100
	}
	//KeyGen
	SK, err := fsac.KeyGen(MPK, MSK, userAttrs)
	require.NoError(t, err)
	require.NotNil(t, SK)

	//SanKeyGen
	Key, err := fsac.SanKeyGen(MPK)
	require.NoError(t, err)
	require.NotNil(t, SK)

	//Encrypt
	Mes := "Secret"
	policy := GeneratePolicy(5)
	CT, err := fsac.Encrypt(MPK, Mes, policy)
	if err != nil {
		t.Errorf("fail to generate ABE ciphertext")
		return
	}

	//CipherCheck
	resultCipher, _ := fsac.CipherCheck(MPK, CT, userAttrs)
	fmt.Printf("CipherCheck Result : %v\n", resultCipher)

	//Santize
	ctSan, VKey, err := fsac.Santize(MPK, Key, CT)
	if err != nil {
		t.Errorf("fail to generate santized ciphertext")
		return
	}

	//Decrypt
	recoverMes, err := fsac.Decrypt(MPK, CT, SK, VKey, Key, ctSan)
	fmt.Printf("recoverMes=%v\n", recoverMes)
}
