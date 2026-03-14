package DT

import (

	//"pvgss/crypto/dleq"

	"crypto/rand"
	"math/big"

	"github.com/WXY1313/Trade/Crypto/CPABE"
	"github.com/WXY1313/Trade/Crypto/LSSS"
	Sub "github.com/WXY1313/Trade/Crypto/Subscribe"
	"github.com/fentec-project/bn256"
	// "github.com/stretchr/testify/assert"
)

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type DTCiphertext struct {
	Policy string
	Com    *bn256.G1
	C1     *CPABE.ABECiphertext
	C2     *bn256.G1
	C2Com  *bn256.G1
	C3     *Sub.SubCiphertext
}

type ReKey struct {
	D1 *bn256.G1
	D2 *bn256.G1
	D3 *bn256.G1
}

func Setup() (*CPABE.MPK, *CPABE.MSK, *Sub.SPK, *Sub.SSK) {
	//KGC invokes ABE.Setup
	MPK, MSK, _ := CPABE.Setup()
	//Seller invokes Sub.Setup
	SPK, SSK, _ := Sub.Setup(MPK)

	return MPK, MSK, SPK, SSK
}

func AKGen(MPK *CPABE.MPK, MSK *CPABE.MSK, su []string) *CPABE.SK {
	AK, _ := CPABE.KeyGen(MPK, MSK, su)
	return AK
}

func Encrypt(MPK *CPABE.MPK, SPK *Sub.SPK, policy string, s *big.Int, pko *bn256.G1) (*DTCiphertext, [][]*big.Int) {
	//1.Construct the Trade policy:\tau_{trade}=2-of-(1-of-(P_seller,P_sub),P_buyer))
	root := LSSS.NewNode(false, 2, 2, big.NewInt(int64(0)))
	P_buyer := LSSS.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_pay := LSSS.NewNode(false, 2, 1, big.NewInt(int64(2)))
	root.Children = []*LSSS.Node{P_buyer, P_pay}
	P_per := LSSS.NewNode(true, 0, 1, big.NewInt(int64(1)))
	P_sub := LSSS.NewNode(true, 0, 1, big.NewInt(int64(2)))
	P_pay.Children = []*LSSS.Node{P_per, P_sub}
	matrix := LSSS.Convert(root)

	com := new(bn256.G1).ScalarMult(MPK.G1, s)
	shares, _ := LSSS.LSSSShare(s, matrix)
	//Generate P_buyer ciphertext C1
	ABECT, _ := CPABE.Encrypt(MPK, shares[0], policy)
	//Generate P_per ciphertext C2
	c2Com := new(bn256.G1).ScalarMult(MPK.G1, shares[1])
	c2 := new(bn256.G1).ScalarMult(pko, shares[1])
	//Generate P_sub ciphertext C3
	SubCT, _ := Sub.Encrypt(SPK, shares[2])

	return &DTCiphertext{Policy: policy,
		Com:   com,
		C1:    ABECT,
		C2:    c2,
		C2Com: c2Com,
		C3:    SubCT}, matrix
}

func EncVer(MPK *CPABE.MPK, SPK *Sub.SPK, CT *DTCiphertext, matrix [][]*big.Int, pko *bn256.G1) bool {
	if !CPABE.CipherCheck(MPK, CT.C1) {
		return false
	}
	if !Sub.CipherCheck(SPK, CT.C3) {
		return false
	}

	var shareCom []*bn256.G1
	shareCom = append(shareCom, CT.C1.Com, CT.C2Com, CT.C3.Com)

	I1 := make([]int, 2)
	I1[0] = 0
	I1[1] = 1
	rows := len(I1)
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		recMatrix[i] = matrix[I1[i]][:rows]
	}
	invRecMatrix, _ := LSSS.GaussJordanInverse(recMatrix)
	isShareValid, _ := LSSS.GrpLSSSReconG1(invRecMatrix, shareCom, I1)
	if !CPABE.G1Equal(isShareValid, CT.Com) {
		return false
	}
	I2 := make([]int, 2)
	I2[0] = 0
	I2[1] = 1
	rows = len(I2)
	recMatrix = make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		recMatrix[i] = matrix[I2[i]][:rows]
	}
	invRecMatrix, _ = LSSS.GaussJordanInverse(recMatrix)
	isShareValid, _ = LSSS.GrpLSSSReconG1(invRecMatrix, shareCom, I2)
	if !CPABE.G1Equal(isShareValid, CT.Com) {
		return false
	}
	return true
}

func ReKeyGen(MPK *CPABE.MPK, CT *DTCiphertext, sko *big.Int, pko, pku *bn256.G1) *ReKey {
	r, _ := rand.Int(rand.Reader, bn256.Order)
	d1 := new(bn256.G1).ScalarMult(MPK.G1, r)
	d2 := new(bn256.G1).ScalarMult(pko, r)
	skoInv := new(big.Int).ModInverse(sko, bn256.Order)
	skoInv = skoInv.Mod(skoInv, bn256.Order)
	d3 := new(bn256.G1).ScalarMult(CT.C2, skoInv)
	d3 = d3.Add(d3, new(bn256.G1).ScalarMult(pku, r))
	return &ReKey{D1: d1, D2: d2, D3: d3}
}

func ReKeyVer(MPK *CPABE.MPK, CT *DTCiphertext, rekey *ReKey, vko, vku *bn256.G2) bool {
	if !CPABE.GTEqual(bn256.Pair(rekey.D2, MPK.G2), bn256.Pair(rekey.D1, vko)) {
		return false
	}
	if !CPABE.GTEqual(bn256.Pair(rekey.D3, vko), new(bn256.GT).Add(bn256.Pair(CT.C2, MPK.H2), bn256.Pair(rekey.D2, vku))) {
		return false
	}
	return true
}

func PerDecrypt(MPK *CPABE.MPK, CT *DTCiphertext, matrix [][]*big.Int, rekey *ReKey, sku *big.Int, AK *CPABE.SK) *bn256.GT {
	decShare := make([]*bn256.GT, 2)
	decShare[0], _ = CPABE.Decrypt(MPK, CT.C1, AK)
	tempLeft := new(bn256.G1).ScalarMult(rekey.D1, sku)
	tempLeft = tempLeft.Add(rekey.D3, new(bn256.G1).Neg(tempLeft))
	decShare[1] = bn256.Pair(tempLeft, MPK.U2)

	I := make([]int, 2)
	I[0] = 0
	I[1] = 1
	rows := len(I)
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		recMatrix[i] = matrix[I[i]][:rows]
	}
	invRecMatrix, _ := LSSS.GaussJordanInverse(recMatrix)
	S, _ := LSSS.GrpLSSSReconGT(invRecMatrix, decShare, I)
	return S
}

func SubKeyGen(SPK *Sub.SPK, SSK *Sub.SSK, pku *bn256.G1) *Sub.SubKey {
	SK, _ := Sub.KeyGen(SPK, SSK, pku)
	return SK
}

func SubKeyVer(SPK *Sub.SPK, SK *Sub.SubKey, vku *bn256.G2) bool {
	KeyValid := Sub.KeyCheck(SPK, SK, vku)
	return KeyValid
}

func SubDecrypt(MPK *CPABE.MPK, SPK *Sub.SPK, CT *DTCiphertext, matrix [][]*big.Int, SK *Sub.SubKey, sku *big.Int, AK *CPABE.SK) *bn256.GT {
	decShare := make([]*bn256.GT, 2)
	decShare[0], _ = CPABE.Decrypt(MPK, CT.C1, AK)
	decShare[1], _ = Sub.Decrypt(SPK, CT.C3, SK, sku)

	I := make([]int, 2)
	I[0] = 0
	I[1] = 2
	rows := len(I)
	recMatrix := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		recMatrix[i] = matrix[I[i]][:rows]
	}
	invRecMatrix, _ := LSSS.GaussJordanInverse(recMatrix)
	S, _ := LSSS.GrpLSSSReconGT(invRecMatrix, decShare, I)
	return S
}
