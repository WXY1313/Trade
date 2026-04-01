package FSAC

import (
	"bytes"
	"fmt"
	"log"
	"math/big"
	"strconv"

	"github.com/WXY1313/Trade/Crypto/CPABE/Threshold/lsss"
	"github.com/WXY1313/Trade/Crypto/CPABE/Threshold/node"
	"github.com/WXY1313/Trade/Crypto/SymEnc"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/sample"
)

type MPK struct {
	G1      *bn256.G1
	G2      *bn256.G2
	H1      *bn256.G1
	H2      *bn256.G2
	AlphaG1 *bn256.G1
	AlphaGT *bn256.GT
	HXsG1   map[string]*bn256.G1
	HXsG2   map[string]*bn256.G2
	Order   *big.Int
}

type SK struct {
	K   *bn256.G1
	L   *bn256.G2
	KXs map[string]*bn256.G2
}

type Key struct {
	SK *big.Int
	PK *bn256.GT
}

type VKey struct {
	V0 *bn256.GT
	V1 *bn256.GT
}

type FSAC struct {
	P *big.Int
}

type FSACCiphertext struct {
	CT     []byte
	Policy *node.Node           // (M, ρ)
	C      *bn256.GT            //C=h1^m*g1^{alpha*beta}
	_C     *bn256.G2            //_C=h2^{beta}
	C1     map[string]*bn256.G1 //Ci  = hG1^{λi}hiG1^{-ri}
	C2     map[string]*bn256.G1 //Ci' = g1^{ri}
}

func NewFSAC() *FSAC {
	return &FSAC{P: bn256.Order}
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

func Setup() (*MPK, *bn256.G1, error) {
	//Generate sytem attribute set
	var attributeUniverse []string
	for i := 1; i <= 100; i++ {
		attributeUniverse = append(attributeUniverse, "Attr"+strconv.Itoa(i)) // Attr1, Attr2, ..., Attr100
	}
	sampler := sample.NewUniformRange(big.NewInt(1), NewFSAC().P)
	//The group elements
	gG1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	gG2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	a, _ := sampler.Sample()
	alpha, _ := sampler.Sample()
	hG1 := new(bn256.G1).ScalarBaseMult(a)
	hG2 := new(bn256.G2).ScalarBaseMult(a)
	FSACMSK := new(bn256.G1).ScalarBaseMult(alpha)
	alphaGT := new(bn256.GT).ScalarBaseMult(alpha)
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

	FSACMPK := &MPK{
		G1:      gG1,
		G2:      gG2,
		H1:      hG1,
		H2:      hG2,
		AlphaGT: alphaGT,
		HXsG1:   hxsG1,
		HXsG2:   hxsG2,
		Order:   bn256.Order,
	}

	return FSACMPK, FSACMSK, nil
}

func KeyGen(MPK *MPK, MSK *bn256.G1, su []string) (*SK, error) {
	//t←Zp,L=g^t
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	t, _ := sampler.Sample()
	k := new(bn256.G1).Add(MSK, new(bn256.G1).ScalarMult(MPK.H1, t))
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

func SanKeyGen(MPK *MPK) (*Key, error) {
	//t←Zp,L=g^t
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	sk, _ := sampler.Sample()
	pk := new(bn256.GT).ScalarBaseMult(sk)
	return &Key{SK: sk, PK: pk}, nil
}

func Encrypt(MPK *MPK, Mes string, policy *node.Node) (*FSACCiphertext, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	C1Set := make(map[string]*bn256.G1)
	C2Set := make(map[string]*bn256.G1)
	//Generate the ABE ciphertext
	k, _ := sampler.Sample()
	K := new(bn256.GT).ScalarBaseMult(k)
	ct := SymEnc.XOREncryptDecrypt([]byte(Mes), SymEnc.KDF(K))
	fmt.Printf("CT=%v\n", string(ct))

	s, _ := sampler.Sample()
	c := new(bn256.GT).Add(K, new(bn256.GT).ScalarMult(MPK.AlphaGT, s))
	_c := new(bn256.G2).ScalarMult(MPK.G2, s)
	//LSSS.Share -> λi = Mi · v，v[0] = beta
	lambdaI, err := lsss.Share(s, policy)
	if err != nil {
		return nil, err
	}

	for _, at := range node.RowToAttrib(policy) {
		//ri<-Zp
		ri, _ := sampler.Sample()
		HxG1i := MPK.HXsG1[at]
		//ci = h^{a*lambdai}*hi^-ri
		C1Set[at] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(MPK.H1, lambdaI[at]), new(bn256.G1).Neg(new(bn256.G1).ScalarMult(HxG1i, ri)))
		//ci'=h^ri
		C2Set[at] = new(bn256.G1).ScalarMult(MPK.G1, ri)
	}

	return &FSACCiphertext{
		CT:     ct,
		Policy: policy, // (M, ρ)
		C:      c,      //C=e(hG1,uG2)^me(hG1,uG2)^{alpha*beta}
		_C:     _c,     //_C=gG2^{beta}
		C1:     C1Set,  //Ci  = h^{a*λi}hiG1^{-ri}
		C2:     C2Set,  //Ci' = hG1^{ri}
	}, nil

}

func CipherCheck(MPK *MPK, CT *FSACCiphertext, su []string, path *node.Node) (bool, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	y, _ := sampler.Sample()
	u, _ := sampler.Sample()
	k := new(bn256.G1).Add(new(bn256.G1).ScalarMult(MPK.G1, y), new(bn256.G1).ScalarMult(MPK.H1, u))
	l := new(bn256.G2).ScalarMult(MPK.G2, u)
	//{Kx = hxG2^t}x∈Su
	kxs := make(map[string]*bn256.G2)
	//singleAtt := strings.Split(attributeSet, " ")
	for i := 0; i < len(su); i++ {
		kxs[su[i]] = new(bn256.G2).ScalarMult(MPK.HXsG2[su[i]], u)
	}

	ASet := make(map[string]*bn256.GT)
	for i, _ := range kxs {
		for _, v := range node.RowToAttrib(CT.Policy) {
			if i == v {
				left := bn256.Pair(CT.C1[v], l)
				right := bn256.Pair(CT.C2[v], kxs[i])
				ASet[v] = new(bn256.GT).Add(left, right)
			}
		}
	}
	A, err := lsss.ReconGT(path, ASet)
	if err != nil {
		log.Fatalf("Fail to execute LSSSRecon ,Error: %v", err)
	}
	A = new(bn256.GT).Add(bn256.Pair(k, CT._C), new(bn256.GT).Neg(A))
	if !GTEqual(A, bn256.Pair(new(bn256.G1).ScalarBaseMult(y), CT._C)) {
		fmt.Printf("FSAC CT no Pass the check!!!")
		return false, err
	}
	return true, err
}

func Santize(MPK *MPK, Key *Key, CT *FSACCiphertext) ([]byte, *VKey, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	_k, _ := sampler.Sample()
	_K := new(bn256.GT).ScalarBaseMult(_k)
	sanCT := SymEnc.XOREncryptDecrypt(CT.CT, SymEnc.KDF(_K))
	b, _ := sampler.Sample()
	v0 := new(bn256.GT).ScalarBaseMult(b)
	v1 := new(bn256.GT).Add(_K, new(bn256.GT).ScalarMult(Key.PK, b))
	return sanCT, &VKey{V0: v0, V1: v1}, nil
}

func Decrypt(MPK *MPK, CT *FSACCiphertext, SK *SK, VKey *VKey, Key *Key, ct []byte, path *node.Node) (string, error) {
	ASet := make(map[string]*bn256.GT)
	for i, _ := range SK.KXs {
		for _, v := range node.RowToAttrib(path) {
			if i == v {
				left := bn256.Pair(CT.C1[v], SK.L)
				right := bn256.Pair(CT.C2[v], SK.KXs[i])
				ASet[v] = new(bn256.GT).Add(left, right)
			}
		}
	}
	//R ← LSSS.Recon({ ˜Ri}i∈I , τ )
	A, err := lsss.ReconGT(path, ASet)
	if err != nil {
		log.Fatalf("Fail to execute LSSSRecon ,Error: %v", err)
	}
	A = new(bn256.GT).Add(bn256.Pair(SK.K, CT._C), new(bn256.GT).Neg(A))
	K := new(bn256.GT).Add(CT.C, new(bn256.GT).Neg(A))
	_K := new(bn256.GT).Add(VKey.V1, new(bn256.GT).Neg(new(bn256.GT).ScalarMult(VKey.V0, Key.SK)))
	temp := SymEnc.XOREncryptDecrypt(ct, SymEnc.KDF(K))
	_Mes := SymEnc.XOREncryptDecrypt(temp, SymEnc.KDF(_K))
	return string(_Mes), nil
}
