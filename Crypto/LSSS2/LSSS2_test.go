package pvgss_lsss

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/WXY1313/Trade/Crypto/LSSS"
	"github.com/fentec-project/bn256"
	bn128 "github.com/fentec-project/bn256"
	lib "github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestGSS(t *testing.T) {
	//test GSS based on LSSS
	gss := NewGSS(bn128.Order)

	//shareholders := []string{"holder1", "holder2", "holder3", "holder4", "holder5"}

	// create a msp struct out of the boolean formula
	msp, err := lib.BooleanToMSP("((holder1 AND holder2) OR (holder3 AND holder4)) OR holder5", false)
	if err != nil {
		t.Fatalf("Failed to generate the policy: %v\n", err)
	}
	fmt.Printf("MSP=%v\n", msp)

	//Transfer MSP as Matrix

	// 1. 获取原始矩阵的行数
	rows := msp.Mat.Rows()
	cols := msp.Mat.Cols()

	// 2. 初始化目标结构
	matrixBigInt := make([][]*big.Int, rows)

	// 3. 遍历填充
	for i := 0; i < rows; i++ {
		matrixBigInt[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// msp.Mat[i][j] 本身就是 *big.Int，直接赋值即可
			// 如果需要深拷贝以防后续修改影响原数据，可以使用 new(big.Int).Set(...)
			matrixBigInt[i][j] = msp.Mat[i][j].Mod(msp.Mat[i][j], bn256.Order)
		}
	}

	// 4. 打印结果
	LSSS.PrintMatrix(matrixBigInt)

	verMatrix := LSSS.GenerateParityMatrix(matrixBigInt, bn256.Order)
	LSSS.PrintMatrix(verMatrix)
	verResult, _ := LSSS.MultiplyMatrix(verMatrix, matrixBigInt)
	fmt.Printf("matrix * verMatrix = %v\n", verResult)
	fmt.Printf("BN256 Order = %v\n", bn256.Order)

	//sample share s
	sampler := sample.NewUniform(gss.P)
	s, err := sampler.Sample()
	if err != nil {
		t.Fatalf("Failed to sample: %v\n", err)
	}

	//create shares of s
	shares, err := gss.LSSShare(s, msp)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v\n", err)
	}

	//holder1,holder2 recon
	goodShares := make([]*GSSShare, 0)
	goodShares = append(goodShares, shares[0])
	goodShares = append(goodShares, shares[1])

	reconS, err := gss.LSSSRecon(msp, goodShares)
	if err != nil {
		t.Fatalf("Error LSSSRecon: %v\n", err)
	}
	assert.Equal(t, s, reconS)

	//holder5 recon
	goodShares1 := make([]*GSSShare, 0)
	goodShares1 = append(goodShares1, shares[4])

	reconS, err = gss.LSSSRecon(msp, goodShares1)
	if err != nil {
		t.Fatalf("Error LSSSRecon: %v\n", err)
	}
	assert.Equal(t, s, reconS)

	//bad share of holder1 and holder3
	badShares := make([]*GSSShare, 0)
	badShares = append(badShares, shares[0])
	badShares = append(badShares, shares[2])

	_, err = gss.LSSSRecon(msp, badShares)
	if err != nil {
		fmt.Printf("bad share return LSSSRecon Error: %v\n", err)
	}
	assert.Error(t, err)
}
