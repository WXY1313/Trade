// Generalized Secret Sharing on Shamir SS
package gss

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"Trade/Crypto/CPABE/node"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

func sssShare(secret *big.Int, n, t int) ([]*big.Int, error) {
	if t > n || t <= 0 {
		return nil, errors.New("invalid threshold")
	}
	coeffs := make([]*big.Int, t)
	coeffs[0] = secret
	for i := 1; i < t; i++ {
		r, _ := rand.Int(rand.Reader, bn256.Order)
		coeffs[i] = r
	}

	shares := make([]*big.Int, n)
	for i := 1; i <= n; i++ {
		x := big.NewInt(int64(i))
		y := big.NewInt(0)
		xPower := big.NewInt(1)
		for _, coeff := range coeffs {
			term := new(big.Int).Mul(coeff, xPower)
			y.Add(y, term).Mod(y, bn256.Order)
			xPower.Mul(xPower, x).Mod(xPower, bn256.Order)
		}
		shares[i-1] = y
	}
	return shares, nil
}

func sssReconGT(shares []*bn256.GT, indices []int, t int) (*bn256.GT, error) {
	GT := bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(1)), new(bn256.G2).ScalarBaseMult(big.NewInt(1)))
	if len(shares) < t {
		return nil, fmt.Errorf("not enough shares")
	}

	shares = shares[:t]
	indices = indices[:t]

	// 初始化为 GT 单位元（很关键！）
	result := new(bn256.GT).ScalarMult(GT, big.NewInt(0)) // g^0 = 1

	for i := 0; i < t; i++ {
		xi := big.NewInt(int64(indices[i]))
		yi := shares[i]

		if yi == nil {
			return nil, fmt.Errorf("nil share at index %d", i)
		}

		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		for j := 0; j < t; j++ {
			if i != j {
				xj := big.NewInt(int64(indices[j]))

				// numerator *= -xj
				numerator.Mul(numerator, new(big.Int).Neg(xj))
				numerator.Mod(numerator, bn256.Order)

				// denominator *= (xi - xj)
				diff := new(big.Int).Sub(xi, xj)
				diff.Mod(diff, bn256.Order)

				denominator.Mul(denominator, diff)
				denominator.Mod(denominator, bn256.Order)
			}
		}

		denomInv := new(big.Int).ModInverse(denominator, bn256.Order)
		if denomInv == nil {
			return nil, fmt.Errorf("denominator inverse does not exist")
		}

		li := new(big.Int).Mul(numerator, denomInv)
		li.Mod(li, bn256.Order)

		// 🔥 核心：GT 幂运算
		term := new(bn256.GT).ScalarMult(yi, li)

		// 🔥 累乘
		result.Add(result, term)
	}

	return result, nil
}

// ==========================
// 3. 广义秘密共享 (整合版)
// ==========================

// GssShare 整合了生成和映射逻辑
func GssShare(s *big.Int, AA *node.Node) (map[string]*big.Int, error) {
	if AA == nil {
		return nil, errors.New("access structure is nil")
	}

	// 1. 生成所有份额的线性列表
	var collectShares func(n *node.Node, secret *big.Int) ([]*big.Int, error)
	collectShares = func(n *node.Node, secret *big.Int) ([]*big.Int, error) {
		if n.IsLeaf {
			return []*big.Int{secret}, nil
		}
		nodeShares, err := sssShare(secret, n.Childrennum, n.T)
		if err != nil {
			return nil, err
		}

		var allShares []*big.Int
		for i, child := range n.Children {
			cs, err := collectShares(child, nodeShares[i])
			if err != nil {
				return nil, err
			}
			allShares = append(allShares, cs...)
		}
		return allShares, nil
	}

	allShares, err := collectShares(AA, s)
	if err != nil {
		return nil, err
	}

	// 2. 映射到 Map
	sharesMap := make(map[string]*big.Int)
	idx := 0
	var mapAttrs func(n *node.Node)
	mapAttrs = func(n *node.Node) {
		if n.IsLeaf {
			sharesMap[n.Attribute] = allShares[idx]
			idx++
			return
		}
		for _, child := range n.Children {
			mapAttrs(child)
		}
	}
	mapAttrs(AA)

	return sharesMap, nil
}

func GetLen(node *node.Node) int {
	if node.IsLeaf {
		return 1
	} else {
		length := 0
		for _, child := range node.Children {
			length += GetLen(child)
		}
		return length
	}
}

func GssReconGT(AA *node.Node, shares map[string]*bn256.GT) (*bn256.GT, error) {
	if AA == nil {
		return nil, errors.New("access structure is nil")
	}

	// 定义内部递归函数
	var recon func(n *node.Node) (*bn256.GT, error)
	recon = func(n *node.Node) (*bn256.GT, error) {
		// 1. 叶子节点：查表
		if n.IsLeaf {
			share, ok := shares[n.Attribute]
			if !ok {
				return nil, fmt.Errorf("missing share for %s", n.Attribute)
			}
			return share, nil
		}

		// 2. 非叶子节点：收集子节点结果
		childShares := make([]*bn256.GT, 0, n.T)
		childIndices := make([]int, 0, n.T)

		for i, child := range n.Children {
			share, err := recon(child)
			if err != nil {
				continue // 跳过失败的子节点
			}
			childShares = append(childShares, share)
			childIndices = append(childIndices, i+1) // 索引对应 1, 2, 3...
		}

		// 3. 检查门限
		if len(childShares) < n.T {
			return nil, fmt.Errorf("insufficient shares (need %d)", n.T)
		}

		// 4. 插值
		return sssReconGT(childShares, childIndices, n.T)
	}

	return recon(AA)
}
