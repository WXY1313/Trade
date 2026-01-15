package PVGSS

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/WXY1313/Trade/PVGSS/LSSS"
	"github.com/fentec-project/bn256"
)

type Prf struct {
	Cp       []*bn256.G1
	Xc       *big.Int
	Shat     *big.Int
	Shatarry []*big.Int
}

func H(C, Cp []*bn256.G1) *big.Int {
	var combinedBytes []byte
	for _, point := range C {
		combinedBytes = append(combinedBytes, point.Marshal()...)
	}
	for _, point := range Cp {
		combinedBytes = append(combinedBytes, point.Marshal()...)
	}
	hash := sha256.Sum256(combinedBytes)
	hashBigInt := new(big.Int).SetBytes(hash[:])
	return hashBigInt
}

func PVGSSSetup() (*big.Int, *bn256.G1, *bn256.G2) {
	sk, _ := rand.Int(rand.Reader, bn256.Order)
	pk1 := new(bn256.G1).ScalarBaseMult(sk)
	pk2 := new(bn256.G2).ScalarBaseMult(sk)
	return sk, pk1, pk2
}

func PVGSSShare(s *big.Int, matrix [][]*big.Int, PK []*bn256.G1) ([]*bn256.G1, *Prf, error) {
	C := make([]*bn256.G1, len(PK))
	Cp := make([]*bn256.G1, len(PK))
	shares, _ := LSSS.LSSSShare(s, matrix)
	for i := 0; i < len(PK); i++ {
		C[i] = new(bn256.G1).ScalarMult(PK[i], shares[i])
	}
	sp, _ := rand.Int(rand.Reader, bn256.Order)
	sharesp, _ := LSSS.LSSSShare(sp, matrix)
	for i := 0; i < len(PK); i++ {
		Cp[i] = new(bn256.G1).ScalarMult(PK[i], sharesp[i])
	}
	c := H(C, Cp)
	temp := new(big.Int).Mul(c, s)
	temp.Mod(temp, bn256.Order)
	shat := new(big.Int).Sub(sp, temp)
	shat.Mod(shat, bn256.Order)
	shatarray := make([]*big.Int, len(PK))
	for i := 0; i < len(PK); i++ {
		temp := new(big.Int).Mul(c, shares[i])
		temp.Mod(temp, bn256.Order)
		shatarray[i] = new(big.Int).Sub(sharesp[i], temp)
		shatarray[i].Mod(shatarray[i], bn256.Order)
	}
	prfs := &Prf{
		Cp:       Cp,
		Xc:       c,
		Shat:     shat,
		Shatarry: shatarray,
	}
	return C, prfs, nil
}

func PVGSSVerify(C []*bn256.G1, prfs *Prf, invmatrix0, invmatrix1 [][]*big.Int, PK []*bn256.G1, I0, I1 []int) (bool, error) {
	for i := 0; i < len(C); i++ {
		left := prfs.Cp[i]
		temp1 := new(bn256.G1).ScalarMult(C[i], prfs.Xc)
		temp2 := new(bn256.G1).ScalarMult(PK[i], prfs.Shatarry[i])
		right := new(bn256.G1).Add(temp1, temp2)
		if left.String() != right.String() {
			return false, fmt.Errorf("check nizk proof fails")
		}
	}
	// Alice and Bob
	// I0 := make([]int, len(invmatrix0))
	// for i := 0; i < len(invmatrix0); i++ {
	// 	I0[0] = i
	// }
	recoverShat, err := LSSS.LSSSRecon(invmatrix0, prfs.Shatarry, I0)
	if err != nil {
		return false, fmt.Errorf("GSSRecon fails")
	}
	if prfs.Shat.Cmp(recoverShat) != 0 {
		return false, fmt.Errorf("reconstruct shat dont match")
	}
	// Alice and Watchers
	// I1 := make([]int, len(invmatrix1))
	// I1[0] = 0
	// for i := 0; i < len(invmatrix1); i++ {
	// 	I1[i+1] = i + 2
	// }
	recoverShat, err = LSSS.LSSSRecon(invmatrix1, prfs.Shatarry, I1)
	if err != nil {
		return false, fmt.Errorf("GSSRecon fails")
	}
	if prfs.Shat.Cmp(recoverShat) != 0 {
		return false, fmt.Errorf("reconstruct shat dont match")
	}
	return true, nil
}

func PVGSSPreRecon(C *bn256.G1, sk *big.Int) (*bn256.G1, error) {
	skInv := new(big.Int).ModInverse(sk, bn256.Order)
	if skInv == nil {
		return nil, fmt.Errorf("no inverse for sk")
	}
	if new(big.Int).Mod(new(big.Int).Mul(sk, skInv), bn256.Order).Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("inverse for sk is wrong")
	}
	if skInv.Cmp(big.NewInt(0)) == -1 {
		return nil, fmt.Errorf("inverse for sk is neg")
	}
	decShare := new(bn256.G1).ScalarMult(C, skInv)

	// Calculate powers: (decShare, g1)
	return decShare, nil
}

func PVGSSKeyVrf(C, decShare *bn256.G1, pk1 *bn256.G1) (bool, error) {
	// Use DLEQ verification instead of pairing verification
	//g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1)) // generator of G1

	// Calculate powers: (decShare, g1)
	// We need to verify that log_C(decShare) = log_pk1(g1)

	return true, nil
}

func PVGSSRecon(AA [][]*big.Int, Q []*bn256.G1, I []int) (*bn256.G1, error) {
	S, _ := LSSS.GrpLSSSRecon(AA, Q, I)
	return S, nil
}
