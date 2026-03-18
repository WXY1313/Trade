// Shamir's secret sharing
package sss

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/WXY1313/Trade/Crypto/RSCode"
	"github.com/fentec-project/bn256"
)

func Share(s *big.Int, n, t int) ([]*big.Int, error) {
	// Generate the random coefficients of the polynomial
	cofficients := make([]*big.Int, t)
	cofficients[0] = s
	for i := 1; i < t; i++ {
		cofficients[i], _ = rand.Int(rand.Reader, bn256.Order)
	}

	// Generate secret shares
	shares := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		x := big.NewInt(int64(i + 1))
		shares[i] = evaluatePolynomial(cofficients, x, bn256.Order)
	}
	return shares, nil
}

func Recon(Q []*big.Int, I []*big.Int, threshold int) (*big.Int, error) {
	// 1. 检查输入长度
	if len(Q) < threshold {
		return nil, fmt.Errorf("not enough shares: got %d, need %d", len(Q), threshold)
	}

	// 2. RS Code 验证
	// 假设 RSCode.RSCodeVerify 返回 true 表示合法，false 表示非法
	// 注意：请确保你的 RSCode.RSCodeVerify 实现是正确的（参考之前的回复）
	isValid := RSCode.RSCodeVerify(Q, threshold)

	if !isValid {
		return nil, errors.New("RSCode verification failed: invalid shares detected")
	}

	fmt.Printf("RSCode Verification pass!!!\n")

	// 3. 如果验证通过，继续执行插值逻辑 (之前这里的代码永远没跑到)
	lambdas, err := PrecomputeLagrangeCoefficients(I)
	if err != nil {
		return nil, fmt.Errorf("failed to compute Lagrange coefficients: %w", err)
	}

	secret := big.NewInt(0)
	order := bn256.Order

	for i := 0; i < threshold; i++ {
		if lambdas[i] == nil {
			return nil, fmt.Errorf("lambda coefficient at index %d is nil", i)
		}

		// temp = share_i * lambda_i
		temp := new(big.Int).Mul(Q[i], lambdas[i])
		temp.Mod(temp, order)

		// secret += temp
		secret.Add(secret, temp)
		secret.Mod(secret, order)
	}

	return secret, nil
}

// evaluatePolynomial Compute the value of the polynomial at a given x
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

// Calculate the Lagrangian coefficients, where I is the index corresponding to the shares in Q
func PrecomputeLagrangeCoefficients(I []*big.Int) ([]*big.Int, error) {
	k := len(I)
	if k == 0 {
		return nil, errors.New("input index list is empty")
	}

	order := bn256.Order
	lambdas := make([]*big.Int, k)

	for i := 0; i < k; i++ {
		lambda_i := big.NewInt(1)

		for j := 0; j < k; j++ {
			if i == j {
				continue
			}

			// 检查是否有重复的索引 (x_i == x_j)，这会导致分母为 0
			if I[i].Cmp(I[j]) == 0 {
				return nil, fmt.Errorf("duplicate index detected at positions %d and %d: %v", i, j, I[i])
			}

			// 分子: -x_j
			// 注意：new(big.Int).Neg(I[j]) 会修改 I[j] 本身如果 I[j] 是被共享引用的话？
			// 不，Neg 返回一个新的值，但在大数库中最好显式复制以防万一，不过 big.Int 的 Neg 通常返回新对象或接收者。
			// 为了安全，我们构造临时变量。
			num := new(big.Int).Neg(I[j])

			// 分母: x_i - x_j
			den := new(big.Int).Sub(I[i], I[j])

			// 计算分母的模逆: den^-1 mod order
			denInv := new(big.Int).ModInverse(den, order)
			if denInv == nil {
				// 理论上如果上面检查了 I[i] != I[j] 且 order 是素数，这里不应为 nil
				// 但为了健壮性保留检查
				return nil, fmt.Errorf("failed to compute modular inverse for denominator at i=%d, j=%d", i, j)
			}

			// lambda_i *= num * denInv
			term := new(big.Int).Mul(num, denInv)
			term.Mod(term, order)

			lambda_i.Mul(lambda_i, term)
			lambda_i.Mod(lambda_i, order)
		}
		lambdas[i] = lambda_i
	}

	return lambdas, nil
}
