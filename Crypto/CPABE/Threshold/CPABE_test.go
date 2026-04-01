package CPABE

import (
	"fmt"
	"math/big"
	"strconv"
	"testing"

	"github.com/WXY1313/Trade/Crypto/CPABE/Threshold/node"
	"github.com/WXY1313/Trade/Crypto/Operation"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/require"
)

func TestAll(t *testing.T) {
	//Setup
	MPK, MSK, err := Setup()

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

	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
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
