package PVGSS

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/fentec-project/bn256"

	//"pvgss/crypto/dleq"

	"testing"

	"github.com/WXY1313/Trade/PVGSS/LSSS"
	// "github.com/stretchr/testify/assert"
)

// Performance test
func TestLSSSPVGSS(t *testing.T) {
	nx := 10       // the number of delegated proxies
	tx := nx/2 + 1 // the threshold of proxies
	num := nx + 3  // the number of leaf nodes

	//Construct the Trade policy:
	// \tau_{trade}=2-of-(1-of-(t-of-(P1,...,Pn),P_seller,P_sub),P_buyer)
	root := LSSS.NewNode(false, 2, 2, big.NewInt(int64(0)))
	P_buyer := LSSS.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_pay := LSSS.NewNode(false, 3, 1, big.NewInt(int64(2)))
	root.Children = []*LSSS.Node{P_buyer, P_pay}
	P_proxy := LSSS.NewNode(false, nx, tx, big.NewInt(int64(1)))
	P_seller := LSSS.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_sub := LSSS.NewNode(true, 0, 1, big.NewInt(int64(3)))
	P_pay.Children = []*LSSS.Node{P_proxy, P_seller, P_sub}
	proxySet := make([]*LSSS.Node, nx)
	for i := 0; i < nx; i++ {
		proxySet[i] = LSSS.NewNode(true, 0, 1, big.NewInt(int64(i+1)))
	}
	P_proxy.Children = proxySet

	// 1. PVGSSSetup
	// Key Pairs
	SK := make([]*big.Int, num)
	PK1 := make([]*bn256.G1, num)
	PK2 := make([]*bn256.G2, num)
	for i := 0; i < num; i++ {
		SK[i], PK1[i], PK2[i] = PVGSSSetup()
	}
	matrix := LSSS.Convert(root)
	fmt.Printf("Martrix=%v\n", matrix)

	// 2. PVGSSShare
	// Generate secret values randomly
	secret, _ := rand.Int(rand.Reader, bn256.Order)
	//onrgnS := new(bn256.G1).ScalarBaseMult(secret)
	C, prfs, _ := PVGSSShare(secret, matrix, PK1)

	// 3. PVGSSVerify
	I00 := make([]int, num)
	for i := 0; i < num; i++ {
		I00[i] = i
	}
	rows := len(I00)
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		recMatrix[i] = matrix[I00[i]][:rows]
	}
	fmt.Printf("recMatrix=%v x %v\n", len(recMatrix), len(recMatrix[0]))
	fmt.Println("I00 array:", I00)
	invMatrix, _ := LSSS.GaussJordanInverse(matrix)
	fmt.Printf("recMatrix=%v x %v\n", len(matrix), len(matrix[0]))
	isShareValid, _ := PVGSSVerify(C, prfs, invMatrix, PK1, I00)
	fmt.Printf("invRecMatrix=%v x %v\n", len(invMatrix), len(invMatrix[0]))
	fmt.Println("Off-chain Shares verfication result = ", isShareValid)

	// I00 := make([]int, (num+1)/2)
	// I00[0] = 0
	// for i := 0; i < (num+1)/2-1; i++ {
	// 	I00[i+1] = i + 2
	// }
	// rows := len(I00)
	// recMatrix := make([][]*big.Int, rows)
	// for i := 0; i < rows; i++ {
	// 	recMatrix[i] = matrix[I00[i]][:rows]
	// }
	// fmt.Printf("recMatrix=%v x %v\n", len(recMatrix), len(recMatrix[0]))
	// invRecMatrix, _ := LSSS.GaussJordanInverse(recMatrix)
	// fmt.Printf("invRecMatrix=%v x %v\n", len(invRecMatrix), len(invRecMatrix[0]))
	// isShareValid, _ := PVGSSVerify(C, prfs, invRecMatrix, PK1, I00)
	// fmt.Println("Off-chain Shares verfication result = ", isShareValid)

	// 4. PVGSSPreRecon
	decShares := make([]*bn256.G1, num)
	for i := 0; i < num; i++ {
		decShares[i], _ = PVGSSPreRecon(C[i], SK[i])
	}

	// 5. PVGSSKeyVrf
	// Off-chain
	ofchainIsKeyValid := make([]bool, num)
	for i := 0; i < num; i++ { // It is a example : Verify the decryption keys of Alice and Bob
		ofchainIsKeyValid[i], _ = PVGSSKeyVrf(C[i], decShares[i], PK1[i])
	}
	fmt.Println("Off-chain DecShares verification result = ", ofchainIsKeyValid)

	/*
		// 6. PVGSSRecon
		// A and Watchers
		I := make([]int, 1+tx)
		I[0] = 0
		for i := 0; i < tx; i++ {
			I[i+1] = i + 2
		}
		Q := make([]*bn256.G1, 1+tx)
		for i := 0; i < len(I); i++ {
			Q[i] = decShares[I[i]]
		}
		I00 = make([]int, (num+1)/2)
		I00[0] = 0
		for i := 0; i < (num+1)/2-1; i++ {
			I00[i+1] = i + 2
		}
		rows := len(I00)
		recMatrix := make([][]*big.Int, rows)
		for i := 0; i < rows; i++ {
			recMatrix[i] = matrix[I00[i]][:rows]
		}
		invRecMatrix, _ := LSSS.GaussJordanInverse(recMatrix)
		recMatrix = make([][]*big.Int, rows)
		for i := 0; i < rows; i++ {
			recMatrix[i] = matrix[I[i]][:rows]
		}
		invRecMatrix, _ = LSSS.GaussJordanInverse(recMatrix)

		fmt.Print("start PVFSSRecon\n")
		_, _ = PVGSSRecon(invRecMatrix, Q, I)

		reconS, _ := PVGSSRecon(invRecMatrix, Q, I)
		if onrgnS.String() == reconS.String() {
			fmt.Print("A and Watchers reconstruct secret secessfully!\n")
		}
	*/
}
