// Reed Solomon check
package RSCode

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/fentec-project/bn256"
)

type Node struct {
	IsLeaf      bool
	Children    []*Node
	Childrennum int
	T           int
	Idx         *big.Int
}


// 原理:
// 利用对偶码 C_perp 的性质。如果 shares 是合法的 (属于 C)，则对于任意 c_perp in C_perp，
// 内积 <shares, c_perp> 必须为 0。
// C_perp 由次数 <= n-k-1 的多项式 f(x) 生成，形式为 (v1*f(1), ..., vn*f(n))。
func RSCodeVerify(shares []*big.Int, k int) bool {
	n := len(shares)
	if n < k {
		// 如果份额数量少于或等于阈值，无法进行基于冗余的校验，或者认为总是合法（取决于具体协议定义）
		// 但在 RS 编码理论中，通常 n > k 才有校验意义。
		// 这里假设 n > k 才是需要验证的情况。
		fmt.Printf("number of shares must be greater than threshold k for verification\n")
		return false
	}

	// 1. 随机选择一个多项式 f(x) 用于生成对偶码向量 c_perp
	// f(x) 的次数最高为 n - k - 1
	degF := n - k - 1

	// 生成随机系数 f_0, f_1, ..., f_degF
	fCoeffs := make([]*big.Int, degF+1)
	for i := 0; i <= degF; i++ {
		c, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			return false
		}
		fCoeffs[i] = c
	}

	// 2. 计算对偶码向量 c_perp = (y_1, y_2, ..., y_n)
	// 其中 y_i = v_i * f(i)
	// v_i = Product_{j!=i} (1 / (i - j))
	cPerp := make([]*big.Int, n)

	// 预计算所有 v_i
	// 注意：这里的索引 i 对应的是评估点 x = i+1 (即 1, 2, ..., n)
	for i := 0; i < n; i++ {
		x_i := big.NewInt(int64(i + 1)) // 当前点的 x 坐标 (1-based)
		denom := big.NewInt(1)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			x_j := big.NewInt(int64(j + 1))
			diff := new(big.Int).Sub(x_i, x_j)
			denom.Mul(denom, diff)
			denom.Mod(denom, bn256.Order)
		}

		// 计算 v_i = 1 / Denom mod q
		v_i := new(big.Int).ModInverse(denom, bn256.Order)
		if v_i == nil {
			fmt.Printf("modular inverse failed, q might not be prime or denom is 0\n")
			return false
		}

		// 计算 f(x_i)
		fVal := evalPoly(fCoeffs, x_i, bn256.Order)

		// 计算 y_i = v_i * f(x_i)
		y_i := new(big.Int).Mul(v_i, fVal)
		y_i.Mod(y_i, bn256.Order)

		cPerp[i] = y_i
	}

	// 3. 计算内积 <shares, cPerp>
	innerProduct := big.NewInt(0)
	for i := 0; i < n; i++ {
		term := new(big.Int).Mul(shares[i], cPerp[i])
		term.Mod(term, bn256.Order)
		innerProduct.Add(innerProduct, term)
		innerProduct.Mod(innerProduct, bn256.Order)
	}

	// 4. 验证
	// 如果内积为 0，则通过验证（概率极高是合法份额）
	// 如果内积不为 0，则肯定是非法份额
	if innerProduct.Cmp(big.NewInt(0)) != 0 {
		return false
	}

	return true
}

// evalPoly 计算多项式 f(x) 在点 x 处的值 mod q
// fCoeffs[0] + fCoeffs[1]*x + fCoeffs[2]*x^2 + ...
func evalPoly(coeffs []*big.Int, x *big.Int, q *big.Int) *big.Int {
	result := big.NewInt(0)
	xPow := big.NewInt(1) // x^0

	for _, coeff := range coeffs {
		term := new(big.Int).Mul(coeff, xPow)
		term.Mod(term, q)
		result.Add(result, term)
		result.Mod(result, q)

		xPow.Mul(xPow, x)
		xPow.Mod(xPow, q)
	}
	return result
}
