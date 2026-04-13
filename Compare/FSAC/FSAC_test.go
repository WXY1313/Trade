package FSAC

import (
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"Trade/Crypto/CPABE/node"
	"Trade/Crypto/SymEnc"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/require"
)

func TestAll(t *testing.T) {
	n := float64(1)
	//Setup
	MPK, MSK, err := Setup()
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)

	//KeyGen
	var userAttrs []string
	for i := 1; i <= 20; i++ {
		userAttrs = append(userAttrs, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A100
	}
	//KeyGen
	SK, err := KeyGen(MPK, MSK, userAttrs)
	require.NoError(t, err)
	require.NotNil(t, SK)

	//SanKeyGen
	Key, err := SanKeyGen(MPK)
	require.NoError(t, err)
	require.NotNil(t, SK)

	//Encrypt
	//Access Policy
	nx := 5
	tx := (nx + 1) / 2
	root := node.NewNode(false, 3, 2, big.NewInt(int64(0)), "")
	P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr1")
	P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr2")
	P_1 := node.NewNode(false, nx, tx, big.NewInt(int64(3)), "")
	root.Children = []*node.Node{P_A, P_B, P_1}
	for i := 0; i < nx; i++ {
		P_1.Children = append(P_1.Children, node.NewNode(true, 0, 1, big.NewInt(int64(i+1)), "Attr"+strconv.Itoa(i+3)))
	}

	//Authorized path
	path := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	Path_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr1")
	Path_1 := node.NewNode(false, tx, tx, big.NewInt(int64(3)), "")
	Path_1.Children = P_1.Children[:tx]
	path.Children = []*node.Node{Path_A, Path_1}

	Mes := "Secret"
	k, _ := sampler.Sample()
	GT := bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(1)), new(bn256.G2).ScalarBaseMult(big.NewInt(1)))
	K := new(bn256.GT).ScalarMult(GT, k)
	ct := SymEnc.XOREncryptDecrypt([]byte(Mes), SymEnc.KDF(K))
	fmt.Printf("CT=%v\n", string(ct))

	var CT *FSACCiphertext

	starttime := time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		CT, err = Encrypt(MPK, K, root)
	}
	endtime := time.Now().UnixMicro()
	fmt.Printf("Encrypt Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	if err != nil {
		t.Errorf("fail to generate ABE ciphertext")
		return
	}

	//CipherCheck
	var resultCipher bool
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		resultCipher, _ = CipherCheck(MPK, CT, userAttrs, root, path)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("EncVer Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	fmt.Printf("CipherCheck Result : %v\n", resultCipher)

	//Santize
	ctSan, VKey, err := Santize(MPK, Key, CT, ct)
	if err != nil {
		t.Errorf("fail to generate santized ciphertext")
		return
	}

	//Decrypt

	var _K *bn256.GT
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		K, _K, _ = Decrypt(MPK, CT, SK, VKey, Key, ctSan, root, path)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("Decrypt Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	temp := SymEnc.XOREncryptDecrypt(ctSan, SymEnc.KDF(K))
	recoverMes := SymEnc.XOREncryptDecrypt(temp, SymEnc.KDF(_K))
	fmt.Printf("recoverMes=%v\n", string(recoverMes))
}
