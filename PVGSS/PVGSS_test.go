package PVGSS

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

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
	onrgnS := new(bn256.G1).ScalarBaseMult(secret)
	C, prfs, _ := PVGSSShare(secret, matrix, PK1)

	// 3. PVGSSVerify
	// A and B
	I0 := make([]int, 2)
	I0[0] = 0
	I0[1] = 1
	rows0 := len(I0)
	recMatrix0 := make([][]*big.Int, rows0)
	for i := 0; i < rows0; i++ {
		recMatrix0[i] = matrix[I0[i]][:rows0]
	}
	invRecMatrix0, _ := LSSS.GaussJordanInverse(recMatrix0)

	// A and Watchers
	I00 := make([]int, 1+tx)
	I00[0] = 0
	for i := 0; i < tx; i++ {
		I00[i+1] = i + 2
	}
	rows := len(I00)
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		recMatrix[i] = matrix[I00[i]][:rows]
	}
	invRecMatrix, _ := LSSS.GaussJordanInverse(recMatrix)

	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	// A and Watchers
	// 	_, _ = PVGSSVerify(C, prfs, invRecMatrix0, invRecMatrix, PK1, I0, I00)
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// averageDuration := totalDuration / time.Duration(numRuns)

	// fmt.Printf("%d Wathcers, %d threshold : average PVGSSVerify time over %d runs: %s\n", nx, tx, numRuns, averageDuration)

	// Off-chain
	isShareValid, _ := PVGSSVerify(C, prfs, invRecMatrix0, invRecMatrix, PK1, I0, I00)

	fmt.Println("Off-chain Shares verfication result = ", isShareValid)

	// 4. PVGSSPreRecon
	decShares := make([]*bn256.G1, num)

	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = PVGSSPreRecon(C[0], SK[0])
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// averageDuration := (totalDuration / time.Duration(numRuns))

	// fmt.Printf("one user : average PVGSSPreRecon time over %d runs: %s\n", numRuns, averageDuration)

	for i := 0; i < num; i++ {
		decShares[i], _ = PVGSSPreRecon(C[i], SK[i])
	}

	// 5. PVGSSKeyVrf
	// Off-chain
	ofchainIsKeyValid := make([]bool, 2)

	// startTime := time.Now()
	// for i := 0; i < numRuns; i++ {
	// 	_, _ = PVGSSKeyVrf(C[0], decShares[0], PK2[0], proofs[0])
	// }
	// endTime := time.Now()
	// totalDuration = endTime.Sub(startTime)

	// averageDuration := (totalDuration / time.Duration(numRuns))

	// fmt.Printf("one user : average PVGSSKeyVrf time over %d runs: %s\n", numRuns, averageDuration)

	for i := 0; i < 2; i++ { // It is a example : Verify the decryption keys of Alice and Bob
		ofchainIsKeyValid[i], _ = PVGSSKeyVrf(C[i], decShares[i], PK1[i])
	}
	fmt.Println("Off-chain DecShares verification result = ", ofchainIsKeyValid)

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

	rows = len(I)
	recMatrix = make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		recMatrix[i] = matrix[I[i]][:rows]
	}
	invRecMatrix, _ = LSSS.GaussJordanInverse(recMatrix)

	fmt.Print("start PVFSSRecon\n")
	startTime := time.Now()
	for i := 0; i < numRuns; i++ {
		_, _ = PVGSSRecon(invRecMatrix, Q, I)
	}
	endTime := time.Now()
	totalDuration = endTime.Sub(startTime)

	averageDuration := totalDuration / time.Duration(numRuns)

	fmt.Printf("%d Wathcers, %d watchers and Alice reconstruct the secret : average PVGSSRecon time over %d runs: %s\n", nx, tx, numRuns, averageDuration)

	reconS, _ := PVGSSRecon(invRecMatrix, Q, I)
	if onrgnS.String() == reconS.String() {
		fmt.Print("A and Watchers reconstruct secret secessfully!\n")
	}
}
