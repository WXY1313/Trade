package LSSS

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/fentec-project/bn256"
)

func TestLSSS(t *testing.T) {
	//"AND"-"OR" LSSS
	
	//Threshold LSSS
	root := NewNode(false, 3, 3, big.NewInt(int64(0)))
	P_1 := NewNode(false, 3, 2, big.NewInt(int64(1)))
	P_D := NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_2 := NewNode(false, 3, 1, big.NewInt(int64(3)))
	root.Children = []*Node{P_1, P_D, P_2}
	P_A := NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_B := NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_C := NewNode(true, 0, 1, big.NewInt(int64(3)))
	P_1.Children = []*Node{P_A, P_B, P_C}
	P_E := NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_F := NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_G := NewNode(true, 0, 1, big.NewInt(int64(3)))
	P_2.Children = []*Node{P_E, P_F, P_G}

	matrix := Convert(root)
	fmt.Printf("Matrix=%v\n", matrix)
	verMatrix := GenerateParityMatrix(matrix, bn256.Order)
	PrintMatrix(matrix)
	PrintMatrix(verMatrix)
	verResult, _ := MultiplyMatrix(verMatrix, matrix)
	fmt.Printf("matrix * verMatrix = %v\n", verResult[0])
	fmt.Printf("BN256 Order = %v\n", bn256.Order)
}
