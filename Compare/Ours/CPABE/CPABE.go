package CPABE

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
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

type CPABE struct {
	P *big.Int
}

type SK struct {
	K   *bn256.G1
	L   *bn256.G2
	KXs map[string]*bn256.G2
}

type ABECiphertext struct {
	Message *bn256.GT
	Com     *bn256.G1            // Com = g1^m
	MSP     *abe.MSP             // (M, ρ)
	C       *bn256.G1            //C=h1^m*g1^{alpha*beta}
	_C      *bn256.G2            //_C=h2^{beta}
	C1      map[string]*bn256.G1 //Ci  = w1^{λi}hiG1^{-ri}
	C2      map[string]*bn256.G1 //Ci' = g1^{ri}
	C3      map[string]*bn256.G1 //Ci''=g^{λi}
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

func NewCPABE() *CPABE {
	return &CPABE{P: bn256.Order}
}

func Setup() (*MPK, *MSK, error) {
	//Generate sytem attribute set
	var attributeUniverse []string
	for i := 1; i <= 100; i++ {
		attributeUniverse = append(attributeUniverse, "Attr"+strconv.Itoa(i)) // Attr1, Attr2, ..., Attr100
	}
	sampler := sample.NewUniformRange(big.NewInt(1), NewCPABE().P)
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

// Generate an access structure
func GeneratePolicy(attrCount int) string {
	attrs := make([]string, attrCount)
	for i := 0; i < attrCount; i++ {
		attrs[i] = "Attr" + strconv.Itoa(i+1)
	}
	randInt := func(n int) int {
		r, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
		return int(r.Int64())
	}
	for i := attrCount - 1; i > 0; i-- {
		j := randInt(i + 1)
		attrs[i], attrs[j] = attrs[j], attrs[i]
	}
	var build func([]string) string
	build = func(list []string) string {
		if len(list) == 1 {
			return list[0]
		}
		op := "AND"
		if randInt(2) == 0 {
			op = "OR"
		}
		split := randInt(len(list)-1) + 1 // [1, len-1]
		left := build(list[:split])
		right := build(list[split:])
		return "(" + left + " " + op + " " + right + ")"
	}
	policy := build(attrs)
	if len(policy) > 2 && policy[0] == '(' && policy[len(policy)-1] == ')' {
		policy = policy[1 : len(policy)-1]
	}
	return policy
}

func Encrypt(MPK *MPK, m *big.Int, policy string) (*ABECiphertext, error) {
	fmt.Printf("Policy=%v\n", policy)
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	msp, _ := abe.BooleanToMSP(policy, false)
	fmt.Printf("MSP=%v\n", msp)
	mspRows := msp.Mat.Rows()
	mspCols := msp.Mat.Cols()
	// sanity checks
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}
	attribs := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if attribs[i] {
			return nil, fmt.Errorf("some attributes correspond to" +
				"multiple rows of the MSP struct, the scheme is not secure")
		}
		attribs[i] = true
	}

	//Generate the ABE ciphertext
	// pick random vector v with random s as first element
	// beta ∈ Zp
	v, err := data.NewRandomVector(mspCols, sampler)
	if err != nil {
		return nil, err
	}
	beta := v[0]
	betaInv := new(big.Int).ModInverse(beta, MPK.Order)
	com := new(bn256.G1).ScalarBaseMult(m)
	M := bn256.Pair(new(bn256.G1).ScalarMult(MPK.H1, m), MPK.U2)
	fmt.Printf("Message=%v\n", M)
	c := new(bn256.G1).Add(new(bn256.G1).ScalarMult(MPK.H1, m), new(bn256.G1).ScalarMult(MPK.AlphaG1, beta))
	_c := new(bn256.G2).ScalarMult(MPK.G2, beta)

	lambdaI, err := msp.Mat.MulVec(v)
	if err != nil {
		return nil, err
	}
	if len(lambdaI) != mspRows {
		return nil, fmt.Errorf("wrong lambda len")
	}
	lambda := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		lambda[at] = lambdaI[i].Mod(lambdaI[i], bn256.Order)
	}
	rI, err := data.NewRandomVector(mspRows, sampler)
	r := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		r[at] = rI[i].Mod(rI[i], bn256.Order)
	}
	if err != nil {
		return nil, err
	}

	C1Set := make(map[string]*bn256.G1)
	C2Set := make(map[string]*bn256.G1)
	C3Set := make(map[string]*bn256.G1)
	//Parse the access policy
	for _, at := range msp.RowToAttrib {
		C1Set[at] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(MPK.H1, lambda[at]), new(bn256.G1).Neg(new(bn256.G1).ScalarMult(MPK.HXsG1[at], r[at])))
		C2Set[at] = new(bn256.G1).ScalarMult(MPK.G1, r[at])
		result := new(big.Int).Mul(lambda[at], betaInv)
		result.Mod(result, MPK.Order)
		C3Set[at] = new(bn256.G1).ScalarMult(MPK.H1, result)
	}
	//fmt.Printf("C1Set=%v\n", C1Set)
	return &ABECiphertext{
		Message: M,
		Com:     com,   // Com = gG1^m
		MSP:     msp,   // (M, ρ)
		C:       c,     //C=e(hG1,uG2)^me(hG1,uG2)^{alpha*beta}
		_C:      _c,    //_C=gG2^{beta}
		C1:      C1Set, //Ci  = h^{a*λi}hiG1^{-ri}
		C2:      C2Set, //Ci' = hG1^{ri}
		C3:      C3Set, //Ci''=h^{λi}
	}, nil

}

func Decrypt(MPK *MPK, CT *ABECiphertext, SK *SK) (*bn256.GT, error) {
	// find out which attributes are valid and extract them
	goodMatRows := make([]data.Vector, 0)
	goodAttribs := make([]string, 0)
	aToK := make(map[string]*bn256.G2)
	for at, k := range SK.KXs {
		aToK[at] = k
	}
	for i, at := range CT.MSP.RowToAttrib {
		if aToK[at] != nil {
			goodMatRows = append(goodMatRows, CT.MSP.Mat[i])
			goodAttribs = append(goodAttribs, at)
		}
	}
	goodMat, err := data.NewMatrix(goodMatRows)
	if err != nil {
		return nil, err
	}
	//choose consts c_x, such that \sum c_x A_x = (1,0,...,0)
	// if they don't exist, keys are not ok
	goodCols := goodMat.Cols()
	if goodCols == 0 {
		return nil, fmt.Errorf("no good matrix columns, most likely the keys contain no valid attribute")
	}
	one := data.NewConstantVector(goodCols, big.NewInt(0))
	one[0] = big.NewInt(1)
	c, err := data.GaussianEliminationSolver(goodMat.Transpose(), one, bn256.Order)
	if err != nil {
		return nil, err
	}
	cx := make(map[string]*big.Int)
	for i, at := range goodAttribs {
		cx[at] = c[i]
	}
	// compute intermediate values
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
	// --- 修正这里的打印 ---
	fmt.Println("=== Decryption Intermediate Values (eggLambda) ===")
	for k, v := range eggLambda {
		if v != nil {
			fmt.Printf("Key: %s, Value: %v\n", k, v)
		} else {
			fmt.Printf("Key: %s, Value: <nil>\n", k)
		}
	}
	fmt.Println("==============================================")
	eggs := new(bn256.GT).ScalarBaseMult(big.NewInt(0))

	for _, at := range goodAttribs {
		if eggLambda[at] != nil {
			sign := cx[at].Cmp(big.NewInt(0))
			if sign == 1 {
				eggs.Add(eggs, new(bn256.GT).ScalarMult(eggLambda[at], cx[at]))
			} else if sign == -1 {
				eggs.Add(eggs, new(bn256.GT).ScalarMult(new(bn256.GT).Neg(eggLambda[at]), new(big.Int).Abs(cx[at])))
			}
		} else {
			return nil, fmt.Errorf("missing intermediate result")
		}
	}
	eggs = new(bn256.GT).Add(bn256.Pair(SK.K, CT._C), new(bn256.GT).Neg(eggs))
	M := new(bn256.GT).Add(bn256.Pair(CT.C, MPK.U2), new(bn256.GT).Neg(eggs))
	return M, nil
}
