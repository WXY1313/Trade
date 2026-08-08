package lsss

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/WXY1313/Trade/Crypto/CPABE/node"

	"github.com/fentec-project/bn256"
)

func TestLSSS(t *testing.T) {
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
	//matrix, _ := node.Convert(root)

	// 假设 root2 是之前构建好的树
	secret := big.NewInt(100)

	// 获取份额
	shares, err := Share(secret, root)
	if err != nil {
		panic(err)
	}

	// 直接通过属性获取份额
	if share, ok := shares["Role:Admin"]; ok {
		fmt.Printf("Role:Admin 的份额是: %s\n", share.String())
	}

	if share, ok := shares["Location:CN"]; ok {
		fmt.Printf("Location:CN 的份额是: %s\n", share.String())
	}

	// 遍历所有生成的份额
	sharesG1 := make(map[string]*bn256.G1)
	for attr, share := range shares {
		fmt.Printf("属性: %s -> 份额: %s\n", attr, share)
		sharesG1[attr] = new(bn256.G1).ScalarBaseMult(share)
	}

	//Authorized path
	path := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	P_A = node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr1")
	//P_B = node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr2")
	P_1 = node.NewNode(false, 2, 2, big.NewInt(int64(3)), "")
	path.Children = []*node.Node{P_A, P_1}
	P_11 = node.NewNode(true, 0, 1, big.NewInt(int64(1)), "Attr3")
	P_12 = node.NewNode(true, 0, 1, big.NewInt(int64(2)), "Attr4")
	P_1.Children = []*node.Node{P_11, P_12}
	attrSet := node.RowToAttrib(path)

	Q := make(map[string]*bn256.G1)
	for _, at := range attrSet {
		Q[at] = sharesG1[at]
	}
	recoveredSecret, err := ReconG1(root, Q)
	if err != nil {
		t.Fatalf("Reconstruction failed: %v", err)
	}
	fmt.Println("orignal secret = ", new(bn256.G1).ScalarBaseMult(secret))
	fmt.Println("recover secret = ", recoveredSecret)
}
