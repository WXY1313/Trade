package CPABE

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/WXY1313/Trade/Crypto/CPABE/lsss"
	"github.com/WXY1313/Trade/Crypto/CPABE/node"
	"github.com/WXY1313/Trade/Crypto/Operation"
	"github.com/WXY1313/Trade/Crypto/RScode"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

type MPK struct {
	G1      *bn256.G1
	G2      *bn256.G2
	U1      *bn256.G1
	U2      *bn256.G2
	H1      *bn256.G1
	H2      *bn256.G2
	AlphaG1 *bn256.G1
	HXsG1   map[string]*bn256.G1
	HXsG2   map[string]*bn256.G2
	Order   *big.Int
}

type MSK struct {
	Alpha *big.Int
}

type ABECiphertext struct {
	Message *bn256.GT
	Com     *bn256.G1            // Com = g1^m
	Policy  *node.Node           // (M, ρ)
	C       *bn256.G1            //C=h1^m*g1^{alpha*beta}
	_C      *bn256.G2            //_C=h2^{beta}
	C1      map[string]*bn256.G1 //Ci  = w1^{λi}hiG1^{-ri}
	C2      map[string]*bn256.G1 //Ci' = g1^{ri}
	C3      map[string]*bn256.G1 //Ci''=g^{λi}
}

func Setup() (*MPK, *MSK, error) {
	//Generate sytem attribute set
	var attributeUniverse []string
	for i := 1; i <= 100; i++ {
		attributeUniverse = append(attributeUniverse, "Attr"+strconv.Itoa(i)) // Attr1, Attr2, ..., Attr100
	}
	sampler := sample.NewUniformRange(big.NewInt(1), bn256.Order)
	alpha, _ := sampler.Sample()
	//The group elements
	gG1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	gG2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	h_exponent, _ := sampler.Sample()
	hG1 := new(bn256.G1).ScalarBaseMult(h_exponent)
	hG2 := new(bn256.G2).ScalarBaseMult(h_exponent)
	alphaG1 := new(bn256.G1).ScalarBaseMult(alpha)
	u_exponent, _ := sampler.Sample()
	uG1 := new(bn256.G1).ScalarBaseMult(u_exponent)
	uG2 := new(bn256.G2).ScalarBaseMult(u_exponent)
	//For each x in U: h1x=h1^{rx}, h2x=h2^{rx}
	hxsG1 := make(map[string]*bn256.G1)
	hxsG2 := make(map[string]*bn256.G2)
	for i := 0; i < len(attributeUniverse); i++ {
		//hx := HashToG1(attributeUniverse[i])
		r_i, _ := sampler.Sample()
		hxG1 := new(bn256.G1).ScalarMult(hG1, r_i)
		hxG2 := new(bn256.G2).ScalarMult(hG2, r_i)
		hxsG1[attributeUniverse[i]] = hxG1
		hxsG2[attributeUniverse[i]] = hxG2
	}

	ABEMPK := &MPK{
		G1:      gG1,
		G2:      gG2,
		U1:      uG1,
		U2:      uG2,
		H1:      hG1,
		H2:      hG2,
		AlphaG1: alphaG1,
		HXsG1:   hxsG1,
		HXsG2:   hxsG2,
		Order:   bn256.Order,
	}
	ABEMSK := &MSK{
		Alpha: alpha,
	}

	return ABEMPK, ABEMSK, nil
}

func Encrypt(MPK *MPK, m *big.Int, policy *node.Node) (*ABECiphertext, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)

	attribs := make(map[string]bool)
	// 定义一个内部递归函数来遍历树
	for _, attr := range node.RowToAttrib(policy) {
		if attribs[attr] {
			return nil, fmt.Errorf("some attributes correspond to " +
				"multiple rows of the Node struct, the scheme is not secure")
		}
		attribs[attr] = true
	}

	//Generate the ABE ciphertext
	// pick random vector v with random s as first element
	// beta ∈ Zp
	com := new(bn256.G1).ScalarBaseMult(m)
	beta, _ := sampler.Sample()
	betaInv := new(big.Int).ModInverse(beta, MPK.Order)
	M := bn256.Pair(new(bn256.G1).ScalarMult(MPK.H1, m), MPK.U2)
	c := new(bn256.G1).Add(new(bn256.G1).ScalarMult(MPK.H1, m), new(bn256.G1).ScalarMult(MPK.AlphaG1, beta))
	_c := new(bn256.G2).ScalarMult(MPK.G2, beta)

	lambda, err := lsss.Share(beta, policy)
	if err != nil {
		return nil, err
	}
	rI, err := data.NewRandomVector(len(lambda), sampler)
	r := make(map[string]*big.Int)
	for i, at := range node.RowToAttrib(policy) {
		r[at] = rI[i].Mod(rI[i], bn256.Order)
	}
	if err != nil {
		return nil, err
	}

	C1Set := make(map[string]*bn256.G1)
	C2Set := make(map[string]*bn256.G1)
	C3Set := make(map[string]*bn256.G1)
	//Parse the access policy
	for _, at := range node.RowToAttrib(policy) {
		C1Set[at] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(MPK.H1, lambda[at]), new(bn256.G1).Neg(new(bn256.G1).ScalarMult(MPK.HXsG1[at], r[at])))
		C2Set[at] = new(bn256.G1).ScalarMult(MPK.G1, r[at])
		result := new(big.Int).Mul(lambda[at], betaInv)
		result.Mod(result, MPK.Order)
		C3Set[at] = new(bn256.G1).ScalarMult(MPK.H1, result)
	}

	return &ABECiphertext{
		Message: M,
		Com:     com,    // Com = gG1^m
		Policy:  policy, // (M, ρ)
		C:       c,      //C=e(hG1,uG2)^me(hG1,uG2)^{alpha*beta}
		_C:      _c,     //_C=gG2^{beta}
		C1:      C1Set,  //Ci  = h^{a*λi}hiG1^{-ri}
		C2:      C2Set,  //Ci' = hG1^{ri}
		C3:      C3Set,  //Ci''=h^{λi}
	}, nil
}

func CipherCheck(policy *node.Node, path *node.Node, mpk *MPK, ct *ABECiphertext) bool {
	if !Operation.GTEqual(bn256.Pair(ct.C, mpk.G2), new(bn256.GT).Add(bn256.Pair(ct.Com, mpk.H2), bn256.Pair(mpk.AlphaG1, ct._C))) {
		return false
	}
	var C3Set []*bn256.G1
	for _, at := range node.RowToAttrib(policy) {
		if !Operation.GTEqual(bn256.Pair(ct.C1[at], mpk.G2), new(bn256.GT).Add(bn256.Pair(ct.C3[at], ct._C), bn256.Pair(new(bn256.G1).Neg(ct.C2[at]), mpk.HXsG2[at]))) {
			return false
		}
		C3Set = append(C3Set, ct.C3[at])
	}

	verResultRS, _ := RScode.RecurRSCode(policy, C3Set)
	if !verResultRS {
		return false
	}
	attrSet := node.RowToAttrib(path)
	Q := make(map[string]*bn256.G1)
	for _, at := range attrSet {
		Q[at] = ct.C3[at]
	}
	recoverResult, _ := lsss.ReconG1(policy, Q)
	if !Operation.G1Equal(mpk.H1, recoverResult) {
		return false
	}
	return true
}

type SK struct {
	K   *bn256.G1
	L   *bn256.G2
	KXs map[string]*bn256.G2
}

func KeyGen(MPK *MPK, MSK *MSK, su []string) (*SK, error) {
	//t←Zp,L=g^t
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	t, _ := sampler.Sample()
	k := new(bn256.G1).Add(new(bn256.G1).ScalarMult(MPK.U1, MSK.Alpha), new(bn256.G1).ScalarMult(MPK.H1, t))
	l := new(bn256.G2).ScalarMult(MPK.G2, t) //L=g^t
	//{Kx = hxG2^t}x∈Su
	kxs := make(map[string]*bn256.G2)
	for i := 0; i < len(su); i++ {
		_, ok := MPK.HXsG2[su[i]]
		if !ok {
			return nil, fmt.Errorf("attribute %s not in public parameters", su[i])
		}
		kxs[su[i]] = new(bn256.G2).ScalarMult(MPK.HXsG2[su[i]], t)
	}
	return &SK{K: k, L: l, KXs: kxs}, nil
}

func Decrypt(path *node.Node, MPK *MPK, CT *ABECiphertext, SK *SK) (*bn256.GT, error) {
	_, rowMap := node.Convert(path)
	goodAttribs := make([]string, len(rowMap))
	for i := 0; i < len(rowMap); i++ {
		goodAttribs[i] = rowMap[i].Attribute
	}
	aToK := make(map[string]*bn256.G2)
	for at, k := range SK.KXs {
		aToK[at] = k
	}

	eggLambda := make(map[string]*bn256.GT)
	for _, at := range goodAttribs {
		if CT.C1[at] != nil && CT.C2[at] != nil && CT.C3[at] != nil {
			num := bn256.Pair(CT.C1[at], SK.L)
			num = num.Add(num, bn256.Pair(CT.C2[at], aToK[at]))
			eggLambda[at] = num
		} else {
			fmt.Println(CT.C1[at] != nil && CT.C2[at] != nil && CT.C3[at] != nil)
			return nil, fmt.Errorf("attribute %s not in ciphertext dicts", at)
		}
	}

	eggs, _ := lsss.ReconGT(CT.Policy, eggLambda)
	eggs = new(bn256.GT).Add(bn256.Pair(SK.K, CT._C), new(bn256.GT).Neg(eggs))
	M := new(bn256.GT).Add(bn256.Pair(CT.C, MPK.U2), new(bn256.GT).Neg(eggs))
	return M, nil
}
