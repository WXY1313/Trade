package CPABE

import (
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/WXY1313/Trade/crypto/CPABE/node"
	"github.com/WXY1313/Trade/crypto/Operation"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/require"
)

func TestAll(t *testing.T) {
	n := float64(500)
	//Setup
	MPK, MSK, err := Setup()
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)

	//Test group operation
	r, _ := sampler.Sample()
	var rG1 *bn256.G1
	var rG2 *bn256.G2
	var rGT *bn256.GT
	var Pair *bn256.GT

	starttime := time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		rG1 = new(bn256.G1).ScalarBaseMult(r)
	}
	endtime := time.Now().UnixMicro()
	fmt.Printf("Exp in G1 Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		rG2 = new(bn256.G2).ScalarBaseMult(r)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("Exp in G2 Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		rGT = new(bn256.GT).ScalarBaseMult(r)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("Exp in GT Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))
	fmt.Println(rGT)

	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		Pair = bn256.Pair(rG1, rG2)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("Pair Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))
	fmt.Println(Pair)

	//KeyGen
	var userAttrs []string
	for i := 1; i <= 10; i++ {
		userAttrs = append(userAttrs, "Attr"+strconv.Itoa(i)) // A1, A2, ..., A100
	}
	//KeyGen
	SK, err := KeyGen(MPK, MSK, userAttrs)
	require.NoError(t, err)
	require.NotNil(t, SK)

	//Encrypt
	//Access Policy
	root := node.NewNode(false, 3, 2, big.NewInt(int64(0)), "")
	P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr1")
	P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr2")
	P_1 := node.NewNode(false, 3, 2, big.NewInt(int64(3)), "")
	root.Children = []*node.Node{P_A, P_B, P_1}
	P_11 := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr3")
	P_12 := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr4")
	P_13 := node.NewNode(true, 0, 1, big.NewInt(int64(3)), "Attr5")
	P_1.Children = []*node.Node{P_11, P_12, P_13}

	//Authorized path
	path := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	P_A = node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr1")
	P_1 = node.NewNode(false, 2, 2, big.NewInt(int64(3)), "")
	path.Children = []*node.Node{P_A, P_1}
	P_11 = node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr3")
	P_12 = node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr4")
	P_1.Children = []*node.Node{P_11, P_12}

	m, _ := sampler.Sample()
	ABECT, err := Encrypt(MPK, m, root)
	if err != nil {
		t.Errorf("fail to generate ABE ciphertext")
		return
	}

	//CipherCheck
	verResult := CipherCheck(root, path, MPK, ABECT)
	fmt.Printf("The ciphertext verification is %v\n", verResult)

	//Decrypt

	recoverMessage, err := Decrypt(path, MPK, ABECT, SK)
	if !Operation.GTEqual(ABECT.Message, recoverMessage) {
		t.Fatalf("decryption failed: Kθ mismatch\noriginal: %v\nrecovered: %v",
			ABECT.Message, recoverMessage)
	}
}
