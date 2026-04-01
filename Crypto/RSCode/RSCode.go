package RScode

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/WXY1313/Trade/Crypto/CPABE/Threshold/node"
	"github.com/fentec-project/bn256"
)

func RecurRSCode(AA *node.Node, shares []*bn256.G1) (bool, error) {
	if AA == nil {
		return false, errors.New("AA is empty")
	}
	_, _, err := verifyRecursiveRS(AA, shares, 0)
	if err != nil {
		return false, err
	}
	return true, nil
}

// verifyRecursiveRS 递归验证 G1 份额
func verifyRecursiveRS(AA *node.Node, shares []*bn256.G1, offset int) (int, *bn256.G1, error) {
	// 1. 叶子节点
	if AA.IsLeaf {
		if offset >= len(shares) {
			return 0, nil, fmt.Errorf("leaf node [ID:%v]: insufficient shares (offset %d)", AA.Idx, offset)
		}
		secretPoint := shares[offset]
		return 1, secretPoint, nil
	}

	// 2. 非叶子节点：递归收集子节点的 G1 秘密点
	childSecrets := make([]*bn256.G1, 0, AA.Childrennum)
	currentOffset := offset

	for i := 0; i < AA.Childrennum; i++ {
		if i >= len(AA.Children) || AA.Children[i] == nil {
			return 0, nil, fmt.Errorf("node [ID:%v]: missing child at index %d", AA.Idx, i)
		}
		consumed, childSecret, err := verifyRecursiveRS(AA.Children[i], shares, currentOffset)
		if err != nil {
			return 0, nil, err
		}

		childSecrets = append(childSecrets, childSecret)
		currentOffset += consumed
	}

	n := len(childSecrets)
	k := AA.T

	// 检查门限
	if n < k {
		return 0, nil, fmt.Errorf("node [ID:%v]: insufficient child secrets (%d < %d)", AA.Idx, n, k)
	}

	// 3. 调用 RS 验证 (针对 G1 点的版本)
	if !rscodeVerifyG1(childSecrets, k) {
		return 0, nil, fmt.Errorf("node [ID:%v]: RS Code verification failed", AA.Idx)
	}

	// 4. 恢复当前节点的 G1 秘密点
	// 使用拉格朗日插值法恢复常数项 (Secret Point)
	// 输入点: (1, childSecrets[0]), (2, childSecrets[1]), ...
	targetPoint, err := interpolateG1(childSecrets[:k])
	if err != nil {
		return 0, nil, fmt.Errorf("node [ID:%v]: reconstruction failed: %w", AA.Idx, err)
	}

	return currentOffset - offset, targetPoint, nil
}

func rscodeVerifyG1(shares []*bn256.G1, k int) bool {
	n := len(shares)
	if n == k {
		fmt.Printf("This is \"AND\" structure, skips the RSCode verification!\n")
		return true
	}
	if n < k {
		return false
	}

	// 1. 生成随机多项式 f(x) 和 对偶码字 cPerp (逻辑不变)
	degF := n - k - 1
	fCoeffs := make([]*big.Int, degF+1)
	for i := 0; i <= degF; i++ {
		c, _ := rand.Int(rand.Reader, bn256.Order)
		fCoeffs[i] = c
	}

	cPerp := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		// ... (保持原有的 cPerp 计算逻辑不变) ...
		// 为了简洁，这里省略重复代码，逻辑同上文
		x_i := big.NewInt(int64(i + 1))
		denom := big.NewInt(1)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			x_j := big.NewInt(int64(j + 1))
			diff := new(big.Int).Sub(x_i, x_j)
			denom.Mul(denom, diff)
		}
		v_i := new(big.Int).ModInverse(denom, bn256.Order)
		fVal := evaluatePolynomial(fCoeffs, x_i, bn256.Order)
		cPerp[i] = new(big.Int).Mul(v_i, fVal)
		cPerp[i].Mod(cPerp[i], bn256.Order)
	}

	// 2. 使用你提供的方式验证
	// 生成一个随机的非零点 H1 作为“锚点”
	// 注意：H1 必须是 G1 上的一个有效点，且不能是无穷远点
	randScalar, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return false
	}
	H1 := new(bn256.G1).ScalarBaseMult(randScalar)

	// 初始化 sum = H1
	sum := new(bn256.G1).Set(H1)

	// 计算 sum = H1 + Sum(cPerp[i] * shares[i])
	for i := 0; i < n; i++ {
		term := new(bn256.G1).ScalarMult(shares[i], cPerp[i])
		sum.Add(sum, term)
	}

	// 验证 sum 是否等于 H1
	// 如果 Sum(cPerp[i] * shares[i]) == 0，则 sum == H1 + 0 == H1
	return bytes.Equal(sum.Marshal(), H1.Marshal())
}

// interpolateG1 使用拉格朗日插值法从 G1 点恢复秘密点 (常数项)
// 假设 x 坐标为 1, 2, ..., k
func interpolateG1(points []*bn256.G1) (*bn256.G1, error) {
	k := len(points)
	if k == 0 {
		return nil, errors.New("no points provided")
	}

	secret := new(bn256.G1).ScalarBaseMult(big.NewInt(0))

	for i := 0; i < k; i++ {
		// 计算拉格朗日系数 L_i(0)
		// L_i(0) = Product_{j!=i} (0 - x_j) / (x_i - x_j)
		// 这里 x_m = m + 1
		x_i := big.NewInt(int64(i + 1))

		num := big.NewInt(1) // 分子
		den := big.NewInt(1) // 分母

		for j := 0; j < k; j++ {
			if i == j {
				continue
			}
			x_j := big.NewInt(int64(j + 1))

			// 分子 *= (0 - x_j) = -x_j
			num.Mul(num, new(big.Int).Neg(x_j))
			num.Mod(num, bn256.Order)

			// 分母 *= (x_i - x_j)
			diff := new(big.Int).Sub(x_i, x_j)
			diff.Mod(diff, bn256.Order)
			den.Mul(den, diff)
			den.Mod(den, bn256.Order)
		}

		// 计算系数 = num / den
		denInv := new(big.Int).ModInverse(den, bn256.Order)
		if denInv == nil {
			return nil, errors.New("inverse failed")
		}
		coeff := new(big.Int).Mul(num, denInv)
		coeff.Mod(coeff, bn256.Order)

		// 累加: secret += coeff * points[i]
		term := new(bn256.G1).ScalarMult(points[i], coeff)
		secret.Add(secret, term)
	}

	return secret, nil
}

// evaluatePolynomial 保持不变 (标量运算)
func evaluatePolynomial(coefficients []*big.Int, x, order *big.Int) *big.Int {
	result := new(big.Int).Set(coefficients[0])
	xPower := new(big.Int).Set(x)

	for i := 1; i < len(coefficients); i++ {
		term := new(big.Int).Mul(coefficients[i], xPower)
		term.Mod(term, order)
		result.Add(result, term)
		result.Mod(result, order)

		xPower.Mul(xPower, x)
		xPower.Mod(xPower, order)
	}
	return result
}
