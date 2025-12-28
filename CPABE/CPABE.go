package CPABE

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"strconv"

	"github.com/WXY1313/Trade/LSSS"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/sample"
)

type MPK struct {
	G1      *bn256.G1
	G2      *bn256.G2
	U2      *bn256.G2
	H1      *bn256.G1
	H2      *bn256.G2
	W1      *bn256.G1
	W2      *bn256.G2
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
	K   *bn256.G2
	L   *bn256.G2
	KXs map[string]*bn256.G2
}

type ABECiphertext struct {
	Message *bn256.GT
	Com     *bn256.G1         // Com = g1^m
	MSP     *abe.MSP          // (M, ρ)
	C       *bn256.G1         //C=h1^m*g1^{alpha*beta}
	_C      *bn256.G1         //_C=h1^{beta}
	C1      map[int]*bn256.G1 //Ci  = w1^{λi}hiG1^{-ri}
	C2      map[int]*bn256.G1 //Ci' = g1^{ri}
	C3      map[int]*bn256.G1 //Ci''=g^{λi}
}

func NewCPABE() *CPABE {
	return &CPABE{P: bn256.Order}
}

func (cpabe *CPABE) Setup() (*MPK, *MSK, error) {
	//Generate sytem attribute set
	var attributeUniverse []string
	for i := 1; i <= 100; i++ {
		attributeUniverse = append(attributeUniverse, "Attr"+strconv.Itoa(i)) // Attr1, Attr2, ..., Attr100
	}
	sampler := sample.NewUniformRange(big.NewInt(1), NewCPABE().P)
	d, _ := sampler.Sample()
	alpha, _ := sampler.Sample()
	//The group elements
	gG1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	gG2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	h_exponent, _ := sampler.Sample()
	hG1 := new(bn256.G1).ScalarBaseMult(h_exponent)
	hG2 := new(bn256.G2).ScalarBaseMult(h_exponent)
	alphaG1 := new(bn256.G1).ScalarBaseMult(alpha)
	u_exponent, _ := sampler.Sample()
	uG2 := new(bn256.G2).ScalarBaseMult(u_exponent)
	wG1 := new(bn256.G1).ScalarBaseMult(d)
	wG2 := new(bn256.G2).ScalarBaseMult(d)
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
		U2:      uG2,
		H1:      hG1,
		H2:      hG2,
		W1:      wG1,
		W2:      wG2,
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

func (cpabe *CPABE) KeyGen(MPK *MPK, MSK *MSK, su []string) (*SK, error) {
	//t←Zp,L=g^t
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	t, _ := sampler.Sample()
	k := new(bn256.G2).Add(new(bn256.G2).ScalarMult(MPK.U2, MSK.Alpha), new(bn256.G2).ScalarMult(MPK.W2, t))
	l := new(bn256.G2).ScalarMult(MPK.G2, t) //L=g^t
	//{Kx = hxG2^t}x∈Su
	kxs := make(map[string]*bn256.G2)
	//singleAtt := strings.Split(attributeSet, " ")
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

func (cpabe *CPABE) Encrypt(MPK *MPK, m *big.Int, policy string) (*ABECiphertext, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	C1Set := make(map[int]*bn256.G1)
	C2Set := make(map[int]*bn256.G1)
	C3Set := make(map[int]*bn256.G1)
	//Parse the access policy
	msp, _ := abe.BooleanToMSP(policy, false)
	//Generate the ABE ciphertext
	// beta ∈ Zp
	beta, _ := sampler.Sample()
	com := new(bn256.G1).ScalarBaseMult(m)
	M := bn256.Pair(new(bn256.G1).ScalarMult(MPK.H1, m), MPK.U2)

	c := new(bn256.G1).Add(new(bn256.G1).ScalarMult(MPK.H1, m), new(bn256.G1).ScalarMult(MPK.AlphaG1, beta))
	_c := new(bn256.G1).ScalarMult(MPK.G1, beta)

	//LSSS.Share -> λi = Mi · v，v[0] = beta
	lambdaMap, err := LSSS.Share(msp, beta, MPK.Order)
	if err != nil {
		return nil, err
	}

	for i, lambda := range lambdaMap {
		//ri<-Zp
		ri, _ := sampler.Sample()
		attri := msp.RowToAttrib[i]
		HxG1i := MPK.HXsG1[attri]
		//ci = h^{a*lambdai}*hi^-ri
		C1Set[i] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(MPK.W1, lambda), new(bn256.G1).Neg(new(bn256.G1).ScalarMult(HxG1i, ri)))
		//ci'=h^ri
		C2Set[i] = new(bn256.G1).ScalarMult(MPK.G1, ri)
		//
		C3Set[i] = new(bn256.G1).ScalarMult(MPK.G1, lambda)
	}

	return &ABECiphertext{
		Message: M,
		Com:     com,   // Com = gG1^m
		MSP:     msp,   // (M, ρ)
		C:       c,     //C=e(hG1,uG2)^me(hG1,uG2)^{alpha*beta}
		_C:      _c,    //_C=hG1^{beta}
		C1:      C1Set, //Ci  = h^{a*λi}hiG1^{-ri}
		C2:      C2Set, //Ci' = hG1^{ri}
		C3:      C3Set, //Ci''=h^{λi}
	}, nil

}

func (cpabe *CPABE) Decrypt(MPK *MPK, CT *ABECiphertext, SK *SK) (*bn256.GT, error) {
	p := MPK.Order
	ASet := make(map[int]*bn256.GT)

	//I = {i : ρ(i) ∈ Su}
	for i, _ := range SK.KXs {
		for j, v := range CT.MSP.RowToAttrib {
			if i == v {
				left := bn256.Pair(CT.C1[j], SK.L)
				right := bn256.Pair(CT.C2[j], SK.KXs[i])
				ASet[j] = new(bn256.GT).Add(left, right)
			}
		}
	}
	//R ← LSSS.Recon({ ˜Ri}i∈I , τ )
	A, err := LSSS.Recon(CT.MSP, ASet, p)
	if err != nil {
		log.Fatalf("Fail to execute LSSSRecon ,Error: %v", err)
	}
	A = new(bn256.GT).Add(bn256.Pair(CT._C, SK.K), new(bn256.GT).Neg(A))
	M := new(bn256.GT).Add(bn256.Pair(CT.C, MPK.U2), new(bn256.GT).Neg(A))
	return M, nil
}
