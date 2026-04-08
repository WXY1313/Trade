package gss

import (
	"crypto/rand"
	"fmt"

	"math/big"

	"testing"

	"github.com/WXY1313/Trade/Crypto/CPABE/node"

	"github.com/fentec-project/bn256"
	// "pvgss/crypto/gss"
)

func TestGSS(t *testing.T) {
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

	secret, _ := rand.Int(rand.Reader, bn256.Order)

	// test GrpGSSShare
	shares, err := GssShare(secret, root)
	if err != nil {
		t.Errorf("GSSShare failed: %v", err)
	}
	fmt.Println("Shares generated successfully!")

	if len(shares) != GetLen(root) {
		t.Errorf("Shares length mismatch: expected %d, got %d", GetLen(root), len(shares))
	}

	attrSet := node.RowToAttrib(path)
	Q := make(map[string]*big.Int)
	for _, at := range attrSet {
		Q[at] = shares[at]
	}

	recoveredSecret, _ := GssRecon(path, Q)
	fmt.Println("orignal secret = ", secret)
	fmt.Println("recover secret = ", recoveredSecret)
	// Verify that the recovered secret is the same as the original secret
	if recoveredSecret.Cmp(secret) != 0 {
		t.Errorf("Secret reconstruction mismatch: expected %v, got %v", secret, recoveredSecret)
	}
}
