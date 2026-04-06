package Sub

import (
	"bytes"
	"math/big"

	"github.com/WXY1313/Trade/Crypto/CPABE"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/sample"
)

type SPK struct {
	G1      *bn256.G1
	G2      *bn256.G2
	U1      *bn256.G1
	U2      *bn256.G2
	H1      *bn256.G1
	H2      *bn256.G2
	GammaG1 *bn256.G1
	Order   *big.Int
}

type SSK struct {
	Gamma *big.Int
}

type SubKey struct {
	SK1 *bn256.G1
	SK2 *bn256.G1
}

type SubCiphertext struct {
	M   *bn256.GT
	Com *bn256.G1 // Com = g1^m
	C1  *bn256.G1 //C=h1^m*g1^{alpha*beta}
	C2  *bn256.G2 //_C=h2^{beta}
}

func G1Equal(a, b *bn256.G1) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(a.Marshal(), b.Marshal())
}

func GTEqual(a, b *bn256.GT) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.String() == b.String()
}

func Setup(MPK *CPABE.MPK) (*SPK, *SSK, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), bn256.Order)
	gamma, _ := sampler.Sample()
	gammaG1 := new(bn256.G1).ScalarBaseMult(gamma)

	spk := &SPK{
		G1:      MPK.G1,
		G2:      MPK.G2,
		U1:      MPK.U1,
		U2:      MPK.U2,
		H1:      MPK.H1,
		H2:      MPK.H2,
		GammaG1: gammaG1,
		Order:   MPK.Order,
	}
	ssk := &SSK{
		Gamma: gamma,
	}

	return spk, ssk, nil
}

func KeyGen(spk *SPK, ssk *SSK, pk *bn256.G1) (*SubKey, error) {
	//t←Zp,L=g^t
	sampler := sample.NewUniformRange(big.NewInt(1), spk.Order)
	t, _ := sampler.Sample()
	sk1 := new(bn256.G1).Add(new(bn256.G1).ScalarMult(spk.U1, ssk.Gamma), new(bn256.G1).ScalarMult(pk, t))
	sk2 := new(bn256.G1).ScalarMult(spk.G1, t) //L=g^t
	return &SubKey{SK1: sk1, SK2: sk2}, nil
}

func KeyCheck(spk *SPK, subkey *SubKey, vk *bn256.G2) bool {
	if GTEqual(bn256.Pair(subkey.SK1, spk.G2), new(bn256.GT).Add(bn256.Pair(spk.GammaG1, spk.U2), bn256.Pair(subkey.SK2, vk))) {
		return true
	}
	return false
}

func Encrypt(spk *SPK, m *big.Int) (*SubCiphertext, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), spk.Order)
	com := new(bn256.G1).ScalarBaseMult(m)
	mes := new(bn256.GT).ScalarMult(bn256.Pair(spk.H1, spk.U2), m)
	beta, _ := sampler.Sample()
	c1 := new(bn256.G1).Add(new(bn256.G1).ScalarMult(spk.H1, m), new(bn256.G1).ScalarMult(spk.GammaG1, beta))
	c2 := new(bn256.G2).ScalarMult(spk.G2, beta)

	return &SubCiphertext{
		M:   mes,
		Com: com,
		C1:  c1,
		C2:  c2,
	}, nil
}

func CipherCheck(spk *SPK, ct *SubCiphertext) bool {
	if GTEqual(bn256.Pair(ct.C1, spk.G2), new(bn256.GT).Add(bn256.Pair(ct.Com, spk.H2), bn256.Pair(spk.GammaG1, ct.C2))) {
		return true
	}
	return false
}

func Decrypt(spk *SPK, ct *SubCiphertext, subkey *SubKey, sk *big.Int) (*bn256.GT, error) {
	denominator := bn256.Pair(new(bn256.G1).Add(subkey.SK1, new(bn256.G1).Neg(new(bn256.G1).ScalarMult(subkey.SK2, sk))), ct.C2)
	numerator := bn256.Pair(ct.C1, spk.U2)
	M := new(bn256.GT).Add(numerator, new(bn256.GT).Neg(denominator))
	return M, nil
}
