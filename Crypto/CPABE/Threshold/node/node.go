package node

import (
	"math/big"
)

type Node struct {
	IsLeaf      bool
	Children    []*Node
	Childrennum int
	T           int
	Idx         *big.Int
	Attribute   string
}

func NewNode(IsLeaf bool, num int, T int, idx *big.Int, attribute string) *Node {
	return &Node{
		IsLeaf:      IsLeaf,
		Children:    []*Node{},
		Childrennum: num,
		T:           T,
		Idx:         idx,
		Attribute:   attribute,
	}
}

// RowToAttrib 返回访问树中所有叶子节点对应的属性列表。
// 返回的顺序与 Convert 函数生成矩阵行的顺序一致（通常是深度优先）。
func RowToAttrib(n *Node) []string {
	var attribs []string
	n.dfsAttribs(&attribs)
	return attribs
}

// dfsAttribs 是内部辅助递归函数
func (n *Node) dfsAttribs(list *[]string) {
	if n.IsLeaf {
		*list = append(*list, n.Attribute)
		return
	}
	for _, child := range n.Children {
		child.dfsAttribs(list)
	}
}

func Convert(F_A *Node) ([][]*big.Int, []*Node) {
	// L 存储当前的树结构片段
	L := []*Node{F_A}

	// M 存储矩阵
	M := [][]*big.Int{{big.NewInt(1)}}

	// RowToNode 存储矩阵每一行对应的具体节点
	// 初始时，第一行对应根节点（虽然根节点会被展开，但这保持同步）
	RowToNode := []*Node{F_A}

	m, d := 1, 1
	z := 1 // Control loop

	for z != 0 {
		z = 0
		i := 1
		var n, t int
		var threshold *Node
		var remainingStructure []*Node

		// 1. 寻找下一个需要展开的阈值门
		for i <= m && z == 0 {
			currentStructure := L[i-1]
			threshold, remainingStructure, t, n = ExtractFirstThreshold(currentStructure)

			if threshold != nil {
				z = i
				break
			}
			i++
		}

		if z != 0 {
			// 2. 准备展开
			m2, d2 := n, t
			L2 := remainingStructure // 子节点列表

			// 备份当前状态
			L1 := make([]*Node, len(L))
			copy(L1, L)

			M1 := make([][]*big.Int, len(M))
			for i := range M {
				M1[i] = make([]*big.Int, len(M[i]))
				copy(M1[i], M[i])
			}

			// 备份节点映射
			RowToNode1 := make([]*Node, len(RowToNode))
			copy(RowToNode1, RowToNode)

			m1, d1 := m, d

			// 3. 重新初始化 M, L 和 RowToNode
			// 新的维度：行数 m1 + m2 - 1, 列数 d1 + d2 - 1
			newRows := m1 + m2 - 1
			newCols := d1 + d2 - 1

			M = make([][]*big.Int, newRows)
			L = make([]*Node, newRows)
			RowToNode = make([]*Node, newRows) // 初始化新的映射列表

			for i := range M {
				M[i] = make([]*big.Int, newCols)
				for j := range M[i] {
					M[i][j] = big.NewInt(0)
				}
			}

			// 4. 填充数据 (逻辑与你原有代码一致)

			// A. 展开点之前的行 (保持不变)
			for u := 0; u < z-1; u++ {
				L[u] = L1[u]
				RowToNode[u] = RowToNode1[u] // 映射保持不变
				for v := 0; v < d1; v++ {
					M[u][v] = M1[u][v]
				}
			}

			// B. 展开点本身的行 (被替换为子节点)
			// 这里 L2 包含了 threshold 的所有子节点
			for u := z - 1; u < z+m2-1; u++ {
				childIdx := u - (z - 1)
				L[u] = L2[childIdx]

				// 关键修改：将矩阵的这一行映射到具体的子节点
				RowToNode[u] = L2[childIdx]

				for v := 0; v < d1; v++ {
					M[u][v] = M1[z-1][v]
				}
				a, x := (u+1)-(z-1), (u+1)-(z-1)
				for v := d1; v < d1+d2-1; v++ {
					M[u][v] = big.NewInt(int64(x))
					x = (x * a) % 1000000000000000000
				}
			}

			// C. 展开点之后的行 (下移)
			for u := z + m2 - 1; u < newRows; u++ {
				srcIdx := u - m2 + 1
				L[u] = L1[srcIdx]
				RowToNode[u] = RowToNode1[srcIdx] // 映射保持不变，只是位置下移
				for v := 0; v < d1; v++ {
					M[u][v] = M1[srcIdx][v]
				}
			}

			m, d = newRows, newCols
		}
	}

	return M, RowToNode
}

// Extract Threshold structure
func ExtractFirstThreshold(root *Node) (*Node, []*Node, int, int) {
	if root == nil {
		return nil, nil, 0, 0
	}

	// If it is a leaf node, there is no threshold structure
	if root.IsLeaf {
		return nil, []*Node{root}, 0, 0
	}

	// The first non-leaf node is processed and its threshold structure is extracted
	t := root.T
	n := root.Childrennum
	children := root.Children

	// Returns the threshold structure of the current node, as well as its children
	return &Node{
		IsLeaf:      false,
		Children:    nil,
		Childrennum: n,
		T:           t,
		Idx:         root.Idx,
	}, children, t, n
}
