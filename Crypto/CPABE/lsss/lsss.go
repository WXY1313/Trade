package lsss

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"Trade/Crypto/CPABE/node"
	"Trade/Crypto/CPABE/opmatrix"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

// Share 计算 LSSS 份额并返回 属性 -> 份额 的映射
func Share(s *big.Int, AA *node.Node) (map[string]*big.Int, error) {
	// 1. 生成访问矩阵
	matrix, rowMap := node.Convert(AA)
	if len(matrix) == 0 || len(matrix[0]) == 0 {
		return nil, fmt.Errorf("matrix is empty")
	}

	if len(rowMap) != len(matrix) {
		return nil, fmt.Errorf("attribute count mismatch: matrix rows=%d, attributes=%d", len(matrix), len(rowMap))
	}

	matrixRows := len(matrix)
	matrixCols := len(matrix[0])

	// 3. 构造随机向量 v = [s, y2, y3, ..., y_cols]
	v := make([]*big.Int, matrixCols)
	v[0] = s // 第一个元素是秘密值 s

	// 生成随机数填充剩余部分
	// 注意：这里使用 big.NewInt(256) 仅为示例，生产环境应使用曲线的阶 (Order)
	curveOrder := big.NewInt(256)
	for i := 1; i < matrixCols; i++ {
		r, err := rand.Int(rand.Reader, curveOrder)
		if err != nil {
			return nil, err
		}
		v[i] = r
	}

	// 4. 矩阵乘法：Shares = Matrix * v
	// 将向量 v 转换为列矩阵形式 [[s], [y2], ...]
	vColMatrix := make([][]*big.Int, matrixCols)
	for i, val := range v {
		vColMatrix[i] = []*big.Int{val}
	}

	// 执行乘法
	resultMatrix, err := opmatrix.MultiplyMatrix(matrix, vColMatrix)
	if err != nil {
		return nil, err
	}

	// 5. 将结果绑定到 Map[Attribute] = Share
	sharesMap := make(map[string]*big.Int)

	for i := 0; i < matrixRows; i++ {
		attr := rowMap[i].Attribute
		shareVal := resultMatrix[i][0] // 取出乘法结果矩阵中的值
		sharesMap[attr] = shareVal
	}

	return sharesMap, nil
}

func Recon(AA *node.Node, shares map[string]*big.Int) (*big.Int, error) {
	// 1. 获取矩阵和行对应的节点映射
	// 这里直接调用你刚才修改后的 Convert 函数
	matrix, rowMap := node.Convert(AA)

	// 2. 动态构建索引列表 I
	// 原有的代码依赖全局变量 I，现在我们根据 shares 和 rowMap 动态生成它
	var I []int
	for i, node := range rowMap {
		// 检查该行对应的节点是否是叶子节点（即属性）
		// 并且检查用户是否拥有该属性（shares 中是否存在）
		if node.IsLeaf {
			if _, ok := shares[node.Attribute]; ok {
				I = append(I, i)
			}
		}
	}

	// 如果没有找到任何匹配的属性，无法恢复
	if len(I) == 0 {
		return nil, fmt.Errorf("no valid shares found to satisfy the policy")
	}

	rows := len(I)

	// 3. 以下是你原有的逻辑，基本保持不变
	// Prepare the sub-matrix for reconstruction
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		idx := I[i]
		// 边界检查
		if idx >= len(matrix) {
			return nil, fmt.Errorf("Index %d out of range (matrix has %d rows)", idx, len(matrix))
		}
		// 取前 'rows' 列构建方阵
		if len(matrix[idx]) < rows {
			return nil, fmt.Errorf("Matrix row %d has insufficient columns (%d < %d)", idx, len(matrix[idx]), rows)
		}
		recMatrix[i] = matrix[idx][:rows]
	}

	// Compute Inverse Matrix
	// 调用你原有的函数
	invRecMatrix, err := opmatrix.GaussJordanInverse(recMatrix)
	if err != nil {
		return nil, fmt.Errorf("Matrix inversion failed: %v", err)
	}

	// 构造单位向量 (1, 0, 0...)
	one := make([][]*big.Int, 1)
	one[0] = make([]*big.Int, rows)
	for i := 0; i < rows; i++ {
		one[0][i] = big.NewInt(0)
	}
	one[0][0] = big.NewInt(1)

	// 计算系数向量 w
	w, err := opmatrix.MultiplyMatrix(one, invRecMatrix)
	if err != nil {
		return nil, fmt.Errorf("Matrix multiplication (w) failed: %v", err)
	}

	// 构造共享值向量
	shares2 := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		// 使用动态生成的 I[i] 来获取对应的属性名，进而从 shares map 中取值
		// 这里假设 rowMap[I[i]] 是叶子节点，所以它有 Attribute 字段
		attrName := rowMap[I[i]].Attribute
		if shares[attrName] == nil {
			return nil, fmt.Errorf("share for attribute %s is nil", attrName)
		}
		shares2[i] = []*big.Int{shares[attrName]}
	}

	// 计算最终结果 s = w * shares
	reconS, err := opmatrix.MultiplyMatrix(w, shares2)
	if err != nil {
		return nil, fmt.Errorf("Matrix multiplication (result) failed: %v", err)
	}

	s := reconS[0][0]
	return s, nil
}

/*
func ReconG1(AA *node.Node, shares map[string]*bn256.G1) (*bn256.G1, error) {
	// 1. 获取矩阵和行对应的节点映射
	// 这里直接调用你刚才修改后的 Convert 函数
	matrix, rowMap := node.Convert(AA)

	// 2. 动态构建索引列表 I
	// 原有的代码依赖全局变量 I，现在我们根据 shares 和 rowMap 动态生成它
	var I []int
	for i, node := range rowMap {
		// 检查该行对应的节点是否是叶子节点（即属性）
		// 并且检查用户是否拥有该属性（shares 中是否存在）
		if node.IsLeaf {
			if _, ok := shares[node.Attribute]; ok {
				I = append(I, i)
			}
		}
	}

	// 如果没有找到任何匹配的属性，无法恢复
	if len(I) == 0 {
		return nil, fmt.Errorf("no valid shares found to satisfy the policy")
	}

	rows := len(I)

	// 3. 以下是你原有的逻辑，基本保持不变
	// Prepare the sub-matrix for reconstruction
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		idx := I[i]
		// 边界检查
		if idx >= len(matrix) {
			return nil, fmt.Errorf("Index %d out of range (matrix has %d rows)", idx, len(matrix))
		}
		// 取前 'rows' 列构建方阵
		if len(matrix[idx]) < rows {
			return nil, fmt.Errorf("Matrix row %d has insufficient columns (%d < %d)", idx, len(matrix[idx]), rows)
		}
		recMatrix[i] = matrix[idx][:rows]
	}

	// Compute Inverse Matrix
	// 调用你原有的函数
	invRecMatrix, err := opmatrix.GaussJordanInverse(recMatrix)
	if err != nil {
		return nil, fmt.Errorf("Matrix inversion failed: %v", err)
	}

	// 构造单位向量 (1, 0, 0...)
	one := make([][]*big.Int, 1)
	one[0] = make([]*big.Int, rows)
	for i := 0; i < rows; i++ {
		one[0][i] = big.NewInt(0)
	}
	one[0][0] = big.NewInt(1)

	// 计算系数向量 w
	w, err := opmatrix.MultiplyMatrix(one, invRecMatrix)
	if err != nil {
		return nil, fmt.Errorf("Matrix multiplication (w) failed: %v", err)
	}

	// 构造共享值向量
	shares2 := make([][]*bn256.G1, rows)
	for i := 0; i < rows; i++ {
		// 使用动态生成的 I[i] 来获取对应的属性名，进而从 shares map 中取值
		// 这里假设 rowMap[I[i]] 是叶子节点，所以它有 Attribute 字段
		attrName := rowMap[I[i]].Attribute
		if shares[attrName] == nil {
			return nil, fmt.Errorf("share for attribute %s is nil", attrName)
		}
		shares2[i] = []*bn256.G1{shares[attrName]}
	}

	// 计算最终结果 s = w * shares
	reconS, err := opmatrix.MultiplyMatrixG1(w, shares2)
	if err != nil {
		return nil, fmt.Errorf("Matrix multiplication (result) failed: %v", err)
	}

	s := reconS[0][0]
	return s, nil
}
*/
// Convert 负责将访问树转换为矩阵，并计算出重构所需的系数向量 w
// 修正点：rowMap 改回 []*node.Node
func Convert(AA *node.Node, shares map[string]*bn256.G1) (w [][]*big.Int, rowMap []*node.Node, err error) {
	// 1. 获取矩阵和行对应的节点映射
	// 假设 node.Convert 返回的是 []*node.Node
	matrix, rowMap := node.Convert(AA)

	// 2. 动态构建索引列表 I
	var I []int
	// 修正点：使用下标遍历，确保能正确访问切片中的元素
	for i := 0; i < len(rowMap); i++ {
		nodeItem := rowMap[i]
		if nodeItem.IsLeaf {
			if _, ok := shares[nodeItem.Attribute]; ok {
				I = append(I, i)
			}
		}
	}

	if len(I) == 0 {
		return nil, nil, fmt.Errorf("no valid shares found to satisfy the policy")
	}

	rows := len(I)

	// 3. 构建用于求逆的子矩阵
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		idx := I[i]
		// 边界检查
		if idx >= len(matrix) {
			return nil, nil, fmt.Errorf("Index %d out of range (matrix has %d rows)", idx, len(matrix))
		}
		if len(matrix[idx]) < rows {
			return nil, nil, fmt.Errorf("Matrix row %d has insufficient columns (%d < %d)", idx, len(matrix[idx]), rows)
		}
		recMatrix[i] = matrix[idx][:rows]
	}

	// 4. 计算逆矩阵
	invRecMatrix, err := opmatrix.GaussJordanInverse(recMatrix)
	if err != nil {
		return nil, nil, fmt.Errorf("Matrix inversion failed: %v", err)
	}

	// 5. 计算系数向量 w
	one := make([][]*big.Int, 1)
	one[0] = make([]*big.Int, rows)
	for i := 0; i < rows; i++ {
		one[0][i] = big.NewInt(0)
	}
	one[0][0] = big.NewInt(1)

	w, err = opmatrix.MultiplyMatrix(one, invRecMatrix)
	if err != nil {
		return nil, nil, fmt.Errorf("Matrix multiplication (w) failed: %v", err)
	}

	return w, rowMap, nil
}

// ReconG1 负责利用系数向量 w 和份额 shares 恢复秘密值 s
// 修正点：rowMap 类型为 []*node.Node
func ReconG1(w [][]*big.Int, rowMap []*node.Node, shares map[string]*bn256.G1) (*bn256.G1, error) {
	// 1. 重新构建索引列表 I (逻辑需与 Convert 中完全一致)
	var I []int
	// 修正点：使用下标遍历
	for i := 0; i < len(rowMap); i++ {
		nodeItem := rowMap[i]
		if nodeItem.IsLeaf {
			if _, ok := shares[nodeItem.Attribute]; ok {
				I = append(I, i)
			}
		}
	}

	if len(I) == 0 {
		return nil, fmt.Errorf("no valid shares found during reconstruction")
	}

	rows := len(I)

	// 2. 构造共享值向量 shares2
	shares2 := make([][]*bn256.G1, rows)
	for i := 0; i < rows; i++ {
		// 修正点：通过 rowMap[I[i]] 访问节点
		attrName := rowMap[I[i]].Attribute
		if shares[attrName] == nil {
			return nil, fmt.Errorf("share for attribute %s is nil", attrName)
		}
		shares2[i] = []*bn256.G1{shares[attrName]}
	}

	// 3. 计算最终结果 s = w * shares
	reconS, err := opmatrix.MultiplyMatrixG1(w, shares2)
	if err != nil {
		return nil, fmt.Errorf("Matrix multiplication (result) failed: %v", err)
	}

	s := reconS[0][0]
	return s, nil
}

func ReconGT(AA *node.Node, shares map[string]*bn256.GT) (*bn256.GT, error) {
	// 1. 获取矩阵和行对应的节点映射
	// 这里直接调用你刚才修改后的 Convert 函数
	matrix, rowMap := node.Convert(AA)

	// 2. 动态构建索引列表 I
	// 原有的代码依赖全局变量 I，现在我们根据 shares 和 rowMap 动态生成它
	var I []int
	for i, node := range rowMap {
		// 检查该行对应的节点是否是叶子节点（即属性）
		// 并且检查用户是否拥有该属性（shares 中是否存在）
		if node.IsLeaf {
			if _, ok := shares[node.Attribute]; ok {
				I = append(I, i)
			}
		}
	}

	// 如果没有找到任何匹配的属性，无法恢复
	if len(I) == 0 {
		return nil, fmt.Errorf("no valid shares found to satisfy the policy")
	}

	rows := len(I)

	// 3. 以下是你原有的逻辑，基本保持不变
	// Prepare the sub-matrix for reconstruction
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		idx := I[i]
		// 边界检查
		if idx >= len(matrix) {
			return nil, fmt.Errorf("Index %d out of range (matrix has %d rows)", idx, len(matrix))
		}
		// 取前 'rows' 列构建方阵
		if len(matrix[idx]) < rows {
			return nil, fmt.Errorf("Matrix row %d has insufficient columns (%d < %d)", idx, len(matrix[idx]), rows)
		}
		recMatrix[i] = matrix[idx][:rows]
	}

	// Compute Inverse Matrix
	// 调用你原有的函数
	invRecMatrix, err := opmatrix.GaussJordanInverse(recMatrix)
	if err != nil {
		return nil, fmt.Errorf("Matrix inversion failed: %v", err)
	}

	// 构造单位向量 (1, 0, 0...)
	one := make([][]*big.Int, 1)
	one[0] = make([]*big.Int, rows)
	for i := 0; i < rows; i++ {
		one[0][i] = big.NewInt(0)
	}
	one[0][0] = big.NewInt(1)

	// 计算系数向量 w
	w, err := opmatrix.MultiplyMatrix(one, invRecMatrix)
	if err != nil {
		return nil, fmt.Errorf("Matrix multiplication (w) failed: %v", err)
	}

	// 构造共享值向量
	shares2 := make([][]*bn256.GT, rows)
	for i := 0; i < rows; i++ {
		// 使用动态生成的 I[i] 来获取对应的属性名，进而从 shares map 中取值
		// 这里假设 rowMap[I[i]] 是叶子节点，所以它有 Attribute 字段
		attrName := rowMap[I[i]].Attribute
		if shares[attrName] == nil {
			return nil, fmt.Errorf("share for attribute %s is nil", attrName)
		}
		shares2[i] = []*bn256.GT{shares[attrName]}
	}

	// 计算最终结果 s = w * shares
	reconS, err := opmatrix.MultiplyMatrixGT(w, shares2)
	if err != nil {
		return nil, fmt.Errorf("Matrix multiplication (result) failed: %v", err)
	}

	s := reconS[0][0]
	return s, nil
}
