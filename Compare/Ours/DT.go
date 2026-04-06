package DT

import (

	//"pvgss/crypto/dleq"

	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/WXY1313/Trade/Crypto/CPABE"
	"github.com/WXY1313/Trade/Crypto/CPABE/lsss"
	"github.com/WXY1313/Trade/Crypto/CPABE/node"
	"github.com/WXY1313/Trade/Crypto/Operation"
	"github.com/WXY1313/Trade/Crypto/RScode"
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
	Policy *node.Node
	Com    *bn256.G1
	C1     *CPABE.ABECiphertext
	C2     *bn256.G1
	C2Com  *bn256.G1
	C3     *Sub.SubCiphertext
}

type ReKey struct {
	D1 *bn256.G1
	D2 *bn256.G1
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

func Encrypt(MPK *CPABE.MPK, SPK *Sub.SPK, policy *node.Node, s *big.Int, pko *bn256.G1) *DTCiphertext {
	//1.Construct the Trade policy:\tau_{trade}=2-of-(1-of-(P_seller,P_sub),P_buyer))
	root := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	P_buyer := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "buy")
	P_pay := node.NewNode(false, 2, 1, big.NewInt(int64(2)), "")
	root.Children = []*node.Node{P_buyer, P_pay}
	P_per := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "per")
	P_sub := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "sub")
	P_pay.Children = []*node.Node{P_per, P_sub}

	com := new(bn256.G1).ScalarMult(MPK.G1, s)
	shares, _ := lsss.Share(s, root)
	//Generate P_buyer ciphertext C1
	ABECT, _ := CPABE.Encrypt(MPK, shares["buy"], policy)
	//Generate P_per ciphertext C2
	c2Com := new(bn256.G1).ScalarMult(MPK.G1, shares["per"])
	c2 := new(bn256.G1).ScalarMult(pko, shares["per"])
	//Generate P_sub ciphertext C3
	SubCT, _ := Sub.Encrypt(SPK, shares["sub"])

	return &DTCiphertext{Policy: root,
		Com:   com,
		C1:    ABECT,
		C2:    c2,
		C2Com: c2Com,
		C3:    SubCT}
}

func EncVer(MPK *CPABE.MPK, SPK *Sub.SPK, CT *DTCiphertext, vko *bn256.G2, pathABE *node.Node) bool {
	if !CPABE.CipherCheck(CT.C1.Policy, pathABE, MPK, CT.C1) {
		fmt.Printf("CPABE CT is false!\n")
		return false
	}
	if !Operation.GTEqual(bn256.Pair(CT.C2, MPK.G2), bn256.Pair(CT.C2Com, vko)) {
		fmt.Printf("Per CT is false!\n")
		return false
	}
	if !Sub.CipherCheck(SPK, CT.C3) {
		fmt.Printf("Sub CT is false!\n")
		return false
	}

	var shareCom []*bn256.G1
	shareCom = append(shareCom, CT.C1.Com, CT.C2Com, CT.C3.Com)
	fmt.Printf("")
	verRS, _ := RScode.RecurRSCode(CT.Policy, shareCom)
	if !verRS {
		fmt.Printf("RScode is false!\n")
		return false
	}

	path := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	P_buyer := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "buy")
	P_pay := node.NewNode(false, 1, 1, big.NewInt(int64(2)), "")
	path.Children = []*node.Node{P_buyer, P_pay}
	P_per := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "per")
	P_pay.Children = []*node.Node{P_per}

	Q := make(map[string]*bn256.G1)
	Q["buy"] = shareCom[0]
	Q["per"] = shareCom[1]
	recoverCom, _ := lsss.ReconG1(path, Q)
	if !Operation.G1Equal(recoverCom, CT.Com) {
		fmt.Printf("Recover is false!\n")
		return false
	}

	return true
}

func ReKeyGen(MPK *CPABE.MPK, CT *DTCiphertext, sko *big.Int, pko, pku *bn256.G1) *ReKey {
	r, _ := rand.Int(rand.Reader, bn256.Order)
	d1 := new(bn256.G1).ScalarMult(MPK.G1, r)
	skoInv := new(big.Int).ModInverse(sko, bn256.Order)
	skoInv = skoInv.Mod(skoInv, bn256.Order)
	d2 := new(bn256.G1).ScalarMult(CT.C2, skoInv)
	d2 = d2.Add(d2, new(bn256.G1).ScalarMult(pku, r))
	return &ReKey{D1: d1, D2: d2}
}

func ReKeyVer(MPK *CPABE.MPK, CT *DTCiphertext, rekey *ReKey, vko, vku *bn256.G2) bool {
	if !Operation.GTEqual(bn256.Pair(rekey.D2, MPK.G2), new(bn256.GT).Add(bn256.Pair(CT.C2Com, MPK.H2), bn256.Pair(rekey.D1, vku))) {
		return false
	}
	return true
}

func PerDecrypt(path *node.Node, MPK *CPABE.MPK, CT *DTCiphertext, rekey *ReKey, sku *big.Int, AK *CPABE.SK) *bn256.GT {
	decShare := make(map[string]*bn256.GT, 2)
	decShare["buy"], _ = CPABE.Decrypt(path, MPK, CT.C1, AK)
	tempLeft := new(bn256.G1).ScalarMult(rekey.D1, sku)
	tempLeft = tempLeft.Add(rekey.D2, new(bn256.G1).Neg(tempLeft))
	decShare["per"] = bn256.Pair(tempLeft, MPK.U2)

	DTpath := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	P_buyer := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "buy")
	P_pay := node.NewNode(false, 1, 1, big.NewInt(int64(2)), "")
	DTpath.Children = []*node.Node{P_buyer, P_pay}
	P_per := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "per")
	P_pay.Children = []*node.Node{P_per}
	S, _ := lsss.ReconGT(DTpath, decShare)

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

func SubDecrypt(path *node.Node, MPK *CPABE.MPK, SPK *Sub.SPK, CT *DTCiphertext, matrix [][]*big.Int, SK *Sub.SubKey, sku *big.Int, AK *CPABE.SK) *bn256.GT {
	decShare := make(map[string]*bn256.GT, 2)
	decShare["buy"], _ = CPABE.Decrypt(path, MPK, CT.C1, AK)
	decShare["sub"], _ = Sub.Decrypt(SPK, CT.C3, SK, sku)

	DTpath := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	P_buyer := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "buy")
	P_pay := node.NewNode(false, 1, 1, big.NewInt(int64(2)), "")
	DTpath.Children = []*node.Node{P_buyer, P_pay}
	P_sub := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "sub")
	P_pay.Children = []*node.Node{P_sub}
	S, _ := lsss.ReconGT(DTpath, decShare)
	return S
}
