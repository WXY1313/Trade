// Matrix Operations
package opmatrix

import (
	"fmt"
	"math/big"

	"github.com/fentec-project/bn256"
)

func MultiplyMatrix(A, B [][]*big.Int) ([][]*big.Int, error) {
	//  Get the dimensions of A and B
	n := len(A)    // number of rows in A
	m := len(A[0]) // number of columns in A (also number of rows in B)
	p := len(B[0]) //number of columns of B

	// Check
	if len(B) != m {
		return nil, fmt.Errorf("矩阵 A 的列数和矩阵 B 的行数不匹配")
	}

	C := make([][]*big.Int, n)
	for i := range C {
		C[i] = make([]*big.Int, p)
		for j := range C[i] {
			C[i][j] = big.NewInt(0)
		}
	}

	for i := 0; i < n; i++ {
		for j := 0; j < p; j++ {
			// C[i][j] = A[i][k] * B[k][j]  (from k0 to m-1)
			for k := 0; k < m; k++ {
				temp := new(big.Int)
				temp.Mul(A[i][k], B[k][j]) // A[i][k] * B[k][j]
				C[i][j].Add(C[i][j], temp).Mod(C[i][j], bn256.Order)
				// C[i][j].Add(C[i][j], temp)
			}
		}
	}

	return C, nil
}

func MultiplyMatrixG1(A [][]*big.Int, B [][]*bn256.G1) ([][]*bn256.G1, error) {
	// 1. 获取维度
	n := len(A) // A 的行数
	if n == 0 {
		return nil, fmt.Errorf("矩阵 A 为空")
	}
	m := len(A[0]) // A 的列数

	if len(B) == 0 {
		return nil, fmt.Errorf("矩阵 B 为空")
	}

	// 检查维度匹配: A 的列数 == B 的行数
	if len(B) != m {
		return nil, fmt.Errorf("矩阵维度不匹配: A 的列数 (%d) != B 的行数 (%d)", m, len(B))
	}

	p := len(B[0]) // B 的列数

	// 2. 初始化结果矩阵 C
	// 结果类型是 G1
	C := make([][]*bn256.G1, n)
	for i := range C {
		C[i] = make([]*bn256.G1, p)
		for j := range C[i] {
			// 初始化为 G1 的无穷远点 (Identity Element)
			// 类似于整数乘法中的 0，加法中的 0
			C[i][j] = new(bn256.G1).ScalarBaseMult(big.NewInt(0))
		}
	}

	// 3. 矩阵乘法运算
	for i := 0; i < n; i++ {
		for j := 0; j < p; j++ {
			// 计算 C[i][j] = Sum (A[i][k] * B[k][j])
			// 我们需要一个累加器，初始为 Identity
			sumPoint := new(bn256.G1).ScalarBaseMult(big.NewInt(0))

			for k := 0; k < m; k++ {
				// 跳过空值
				if A[i][k] == nil || B[k][j] == nil {
					continue
				}

				// 1. 标量乘法: temp = A[i][k] * B[k][j]
				// 在 bn256 库中，使用 ScalarMult
				temp := new(bn256.G1).ScalarMult(B[k][j], A[i][k])

				// 2. 群加法: sumPoint = sumPoint + temp
				sumPoint.Add(sumPoint, temp)
			}
			C[i][j] = sumPoint
		}
	}

	return C, nil
}

func MultiplyMatrixGT(A [][]*big.Int, B [][]*bn256.GT) ([][]*bn256.GT, error) {
	// 1. 获取维度
	n := len(A) // A 的行数
	if n == 0 {
		return nil, fmt.Errorf("矩阵 A 为空")
	}
	m := len(A[0]) // A 的列数

	if len(B) == 0 {
		return nil, fmt.Errorf("矩阵 B 为空")
	}

	// 检查维度匹配: A 的列数 == B 的行数
	if len(B) != m {
		return nil, fmt.Errorf("矩阵维度不匹配: A 的列数 (%d) != B 的行数 (%d)", m, len(B))
	}

	p := len(B[0]) // B 的列数

	// 2. 初始化结果矩阵 C
	// 结果类型是 G1
	C := make([][]*bn256.GT, n)
	for i := range C {
		C[i] = make([]*bn256.GT, p)
		for j := range C[i] {
			// 初始化为 G1 的无穷远点 (Identity Element)
			// 类似于整数乘法中的 0，加法中的 0
			C[i][j] = new(bn256.GT).ScalarBaseMult(big.NewInt(0))
		}
	}

	// 3. 矩阵乘法运算
	for i := 0; i < n; i++ {
		for j := 0; j < p; j++ {
			// 计算 C[i][j] = Sum (A[i][k] * B[k][j])
			// 我们需要一个累加器，初始为 Identity
			sumPoint := new(bn256.GT).ScalarBaseMult(big.NewInt(0))

			for k := 0; k < m; k++ {
				// 跳过空值
				if A[i][k] == nil || B[k][j] == nil {
					continue
				}

				// 1. 标量乘法: temp = A[i][k] * B[k][j]
				// 在 bn256 库中，使用 ScalarMult
				temp := new(bn256.GT).ScalarMult(B[k][j], A[i][k])

				// 2. 群加法: sumPoint = sumPoint + temp
				sumPoint.Add(sumPoint, temp)
			}
			C[i][j] = sumPoint
		}
	}

	return C, nil
}

func SetToMatrix(set []*big.Int) [][]*big.Int {
	if set == nil {
		return nil
	}

	matrix := make([][]*big.Int, len(set))

	for i := 0; i < len(set); i++ {
		matrix[i] = make([]*big.Int, 1)
		matrix[i][0] = set[i]
	}
	return matrix
}

func IsZeroMatrixMod(matrix [][]*big.Int) bool {
	if matrix == nil {
		return true
	}

	zero := big.NewInt(0)
	temp := new(big.Int) // 复用对象避免频繁分配

	for _, row := range matrix {
		for _, val := range row {
			if val == nil {
				return false
			}
			// temp = val % order
			temp.Mod(val, bn256.Order)

			if temp.Cmp(zero) != 0 {
				return false
			}
		}
	}
	return true
}

func EqualMatrix(A, B [][]*big.Int) bool {
	if len(A) != len(B) {
		return false
	}
	for i := 0; i < len(A); i++ {
		rowA := A[i]
		rowB := B[i]
		if len(rowA) != len(rowB) {
			return false
		}
		for j := 0; j < len(rowA); j++ {
			valA := rowA[j]
			valB := rowB[j]
			if valA == nil && valB == nil {
				continue
			}
			if valA == nil || valB == nil {
				return false
			}
			if valA.Cmp(valB) != 0 {
				fmt.Printf("%d row %d column is not equal!\n", i, j)
				return false
			}
		}
	}

	return true
}

func PrintMatrix(matrix [][]*big.Int) {
	for _, row := range matrix {
		for _, val := range row {
			fmt.Printf("%s ", val.String())
		}
		fmt.Println()
	}
}

// 1.Generate the transpose of the LSSS matrix
// 2.Gaussian elimination:Reduce to the simplest matrix
// 3.Transform into a system of equations
// 4.Identify free variables
// 5.Assigning values ​​to free variables
func GenerateParityMatrix(M [][]*big.Int) [][]*big.Int {
	if len(M) == 0 || len(M[0]) == 0 {
		return [][]*big.Int{}
	}
	n := len(M)
	d := len(M[0])

	modSub := func(a, b *big.Int) *big.Int {
		res := new(big.Int).Sub(a, b)
		res.Mod(res, bn256.Order)
		if res.Sign() < 0 {
			res.Add(res, bn256.Order)
		}
		return res
	}

	// 1. Generate the transpose of the LSSS matrix M -> A (d x n)
	// A[i][j] = M[j][i]
	A := make([][]*big.Int, d)
	for i := 0; i < d; i++ {
		A[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			A[i][j] = new(big.Int).Set(M[j][i])
			A[i][j].Mod(A[i][j], bn256.Order)
		}
	}

	// 2.Gauss-Jordan Elimination: reduce to the simplest matrix
	pivotCols := []int{}
	currentRow := 0

	// 3.Transform into a system of equations and identify free variables
	for col := 0; col < n && currentRow < d; col++ {
		pivotRow := -1
		for r := currentRow; r < d; r++ {
			if A[r][col].Sign() != 0 {
				pivotRow = r
				break
			}
		}
		if pivotRow == -1 {
			continue
		}
		if pivotRow != currentRow {
			A[currentRow], A[pivotRow] = A[pivotRow], A[currentRow]
		}
		pivotVal := A[currentRow][col]
		invPivot := new(big.Int).ModInverse(pivotVal, bn256.Order)
		if invPivot == nil {
			panic("Fail to compute ModInverse: Matrix singular or P not prime?")
		}

		for c := 0; c < n; c++ {
			A[currentRow][c].Mul(A[currentRow][c], invPivot).Mod(A[currentRow][c], bn256.Order)
		}
		for r := 0; r < d; r++ {
			if r != currentRow && A[r][col].Sign() != 0 {
				factor := A[r][col]
				for c := 0; c < n; c++ {
					// term = factor * A[currentRow][c]
					term := new(big.Int).Mul(factor, A[currentRow][c])
					term.Mod(term, bn256.Order)
					A[r][c] = modSub(A[r][c], term)
				}
			}
		}

		pivotCols = append(pivotCols, col)
		currentRow++
	}

	rank := len(pivotCols)
	numFreeVars := n - rank

	// Mark the pivot column
	isPivotCol := make(map[int]bool)
	for _, pc := range pivotCols {
		isPivotCol[pc] = true
	}

	// Collect free variable column indexes
	freeCols := []int{}
	for c := 0; c < n; c++ {
		if !isPivotCol[c] {
			freeCols = append(freeCols, c)
		}
	}

	// 5. Construct the parity check matrix H (numFreeVars x n)
	H := make([][]*big.Int, numFreeVars)

	for i, freeColIdx := range freeCols {
		H[i] = make([]*big.Int, n)
		for k := 0; k < n; k++ {
			H[i][k] = big.NewInt(0)
		}
		H[i][freeColIdx].Set(big.NewInt(1))

		for row := 0; row < rank; row++ {
			pivotColIdx := pivotCols[row]
			coeff := A[row][freeColIdx]
			val := new(big.Int).Neg(coeff)
			val.Mod(val, bn256.Order)
			if val.Sign() < 0 {
				val.Add(val, bn256.Order)
			}
			H[i][pivotColIdx].Set(val)
		}
	}
	return H
}

// GaussJordanInverse computes the inverse of matrix A using Gauss-Jordan elimination.
// It returns the inverse matrix if it exists, otherwise returns an error.
// @TODO to optimize in the future
func GaussJordanInverse(A [][]*big.Int) ([][]*big.Int, error) {
	p := bn256.Order
	// Check if the matrix is square
	n := len(A)
	for i := 0; i < n; i++ {
		if len(A[i]) != n {
			return nil, fmt.Errorf("matrix must be square")
		}
	}

	// Create augmented matrix [A | I]
	augmented := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		augmented[i] = make([]*big.Int, 2*n)
		for j := 0; j < n; j++ {
			augmented[i][j] = new(big.Int).Set(A[i][j]) // Copy A into the augmented matrix
			augmented[i][n+j] = big.NewInt(0)           // Initialize the right side with 0
		}
		augmented[i][n+i] = big.NewInt(1) // Set the right side to the identity matrix
	}
	// fmt.Print("for1 end\n")

	// Perform Gauss-Jordan elimination
	for i := 0; i < n; i++ {
		// Make the diagonal element 1
		if augmented[i][i].Sign() == 0 {
			// Find a row below row i where the element in column i is non-zero
			found := false
			for j := i + 1; j < n; j++ {
				if augmented[j][i].Sign() != 0 {
					// Swap row i with row j
					augmented[i], augmented[j] = augmented[j], augmented[i]
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("matrix is singular and cannot be inverted")
			}
		}

		// Inverse of the pivot element
		inv := new(big.Int).ModInverse(augmented[i][i], p)
		for j := 0; j < 2*n; j++ {
			augmented[i][j].Mul(augmented[i][j], inv)
			augmented[i][j].Mod(augmented[i][j], p)
		}

		// Eliminate the rest of the column
		for j := 0; j < n; j++ {
			if j != i {
				// Subtract multiples of row i from row j to make the off-diagonal elements 0
				factor := new(big.Int).Set(augmented[j][i])
				for k := 0; k < 2*n; k++ {
					augmented[j][k].Sub(augmented[j][k], new(big.Int).Mul(factor, augmented[i][k]))
					augmented[j][k].Mod(augmented[j][k], p)
				}
			}
		}
	}
	// fmt.Print("for2 end\n")

	// Extract the inverse matrix (right side of the augmented matrix)
	inverse := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		inverse[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			inverse[i][j] = new(big.Int).Set(augmented[i][n+j])
		}
	}
	// fmt.Print("for3 end\n")

	return inverse, nil
}

func MatrixMulVector(A [][]*big.Int, B []*big.Int) ([]*big.Int, error) {
	// 1. 获取维度
	rows := len(A)
	if rows == 0 {
		return nil, fmt.Errorf("矩阵 A 为空")
	}
	cols := len(A[0])

	// 2. 检查向量 B 的维度
	// 矩阵的列数必须等于向量的长度
	if len(B) != cols {
		return nil, fmt.Errorf("维度不匹配: 矩阵 A 有 %d 列，但向量 B 长度为 %d", cols, len(B))
	}

	// 3. 初始化结果向量
	// 结果向量的长度等于矩阵的行数
	result := make([]*big.Int, rows)
	for i := range result {
		result[i] = big.NewInt(0) // 初始化为 0
	}

	// 4. 执行矩阵向量乘法
	for i := 0; i < rows; i++ {
		// 检查每一行的长度是否一致（防御性编程）
		if len(A[i]) != cols {
			return nil, fmt.Errorf("矩阵 A 的第 %d 行长度不一致", i)
		}

		sum := big.NewInt(0)
		for k := 0; k < cols; k++ {
			// 计算 A[i][k] * B[k]
			if A[i][k] == nil || B[k] == nil {
				continue
			}
			product := new(big.Int).Mul(A[i][k], B[k])

			// 累加到 sum
			sum.Add(sum, product)
		}
		// 将计算结果存入结果向量
		// 注意：如果需要在有限域下运算，请在这里加上 .Mod(sum, Order)
		result[i] = sum
	}

	return result, nil
}
