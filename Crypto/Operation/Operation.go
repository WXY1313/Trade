package Operation

import (
	"bytes"
	"math/big"
	"sort"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

func MapToVector(m map[string]*big.Int) data.Vector {

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	vec := make(data.Vector, len(keys))

	for i, k := range keys {
		vec[i] = m[k]
	}

	return vec
}

func GTEqual(a, b *bn256.GT) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.String() == b.String()
}

func G1Equal(a, b *bn256.G1) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(a.Marshal(), b.Marshal())
}

func BigIntEqual(a, b *big.Int) bool {
	return a.Cmp(b) == 0 // 如果 a 和 b 相等，返回 true
}

func RandomInt() *big.Int {
	v, _ := data.NewRandomVector(1, sample.NewUniform(bn256.Order))
	return v[0]
}
