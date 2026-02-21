package FSAC

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"strconv"

	"github.com/WXY1313/Trade/CPABE/LSSS"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
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
	CT  []byte
	MSP *abe.MSP          // (M, ρ)
	C   *bn256.GT         //C=h1^m*g1^{alpha*beta}
	_C  *bn256.G2         //_C=h2^{beta}
	C1  map[int]*bn256.G1 //Ci  = hG1^{λi}hiG1^{-ri}
	C2  map[int]*bn256.G1 //Ci' = g1^{ri}
}

func NewFSAC() *FSAC {
	return &FSAC{P: bn256.Order}
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

// PRG expands seed K into outLen bytes using:
// PRG(K) = H(K||1) || H(K||2) || ... until length >= outLen
func PRG(K *bn256.GT, outLen int) []byte {
	if outLen <= 0 {
		return []byte{}
	}

	// 1️⃣ Canonical serialization
	kBytes := K.Marshal()

	hashLen := sha256.Size
	n := (outLen + hashLen - 1) / hashLen

	result := make([]byte, 0, n*hashLen)

	for counter := uint32(1); counter <= uint32(n); counter++ {
		h := sha256.New()

		// domain separation
		h.Write([]byte("PRG_GT"))

		h.Write(kBytes)

		var ctrBytes [4]byte
		binary.BigEndian.PutUint32(ctrBytes[:], counter)
		h.Write(ctrBytes[:])

		block := h.Sum(nil)
		result = append(result, block...)
	}

	return result[:outLen]
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

func (fsac *FSAC) Setup() (*MPK, *bn256.G1, error) {
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

func (fsac *FSAC) KeyGen(MPK *MPK, MSK *bn256.G1, su []string) (*SK, error) {
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

func (fsac *FSAC) SanKeyGen(MPK *MPK) (*Key, error) {
	//t←Zp,L=g^t
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	sk, _ := sampler.Sample()
	pk := new(bn256.GT).ScalarBaseMult(sk)
	return &Key{SK: sk, PK: pk}, nil
}

func (fsac *FSAC) Encrypt(MPK *MPK, Mes string, policy string) (*FSACCiphertext, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	C1Set := make(map[int]*bn256.G1)
	C2Set := make(map[int]*bn256.G1)
	//Parse the access policy
	msp, _ := abe.BooleanToMSP(policy, false)
	//Generate the ABE ciphertext
	k, _ := sampler.Sample()
	K := new(bn256.GT).ScalarBaseMult(k)
	ct := make([]byte, len([]byte(Mes)))
	subtle.XORBytes(ct, []byte(Mes), PRG(K, len([]byte(Mes))))
	fmt.Printf("CT=%v\n", string(ct))

	s, _ := sampler.Sample()
	c := new(bn256.GT).Add(K, new(bn256.GT).ScalarMult(MPK.AlphaGT, s))
	_c := new(bn256.G2).ScalarMult(MPK.G2, s)
	//LSSS.Share -> λi = Mi · v，v[0] = beta
	lambdaMap, err := LSSS.Share(msp, s, MPK.Order)
	if err != nil {
		return nil, err
	}

	for i, lambda := range lambdaMap {
		//ri<-Zp
		ri, _ := sampler.Sample()
		attri := msp.RowToAttrib[i]
		HxG1i := MPK.HXsG1[attri]
		//ci = h^{a*lambdai}*hi^-ri
		C1Set[i] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(MPK.H1, lambda), new(bn256.G1).Neg(new(bn256.G1).ScalarMult(HxG1i, ri)))
		//ci'=h^ri
		C2Set[i] = new(bn256.G1).ScalarMult(MPK.G1, ri)
	}

	return &FSACCiphertext{
		CT:  ct,
		MSP: msp,   // (M, ρ)
		C:   c,     //C=e(hG1,uG2)^me(hG1,uG2)^{alpha*beta}
		_C:  _c,    //_C=gG2^{beta}
		C1:  C1Set, //Ci  = h^{a*λi}hiG1^{-ri}
		C2:  C2Set, //Ci' = hG1^{ri}
	}, nil

}

func (fsac *FSAC) CipherCheck(MPK *MPK, CT *FSACCiphertext, su []string) (bool, error) {
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

	p := MPK.Order
	ASet := make(map[int]*bn256.GT)
	for i, _ := range kxs {
		for j, v := range CT.MSP.RowToAttrib {
			if i == v {
				left := bn256.Pair(CT.C1[j], l)
				right := bn256.Pair(CT.C2[j], kxs[i])
				ASet[j] = new(bn256.GT).Add(left, right)
			}
		}
	}
	A, err := LSSS.ReconGT(CT.MSP, ASet, p)
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

func (fsac *FSAC) Santize(MPK *MPK, Key *Key, CT *FSACCiphertext) ([]byte, *VKey, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	_k, _ := sampler.Sample()
	_K := new(bn256.GT).ScalarBaseMult(_k)
	sanCT := make([]byte, len(CT.CT))
	subtle.XORBytes(sanCT, CT.CT, PRG(_K, len(CT.CT)))
	b, _ := sampler.Sample()
	v0 := new(bn256.GT).ScalarBaseMult(b)
	v1 := new(bn256.GT).Add(_K, new(bn256.GT).ScalarMult(Key.PK, b))
	return sanCT, &VKey{V0: v0, V1: v1}, nil
}

func (fsac *FSAC) Decrypt(MPK *MPK, CT *FSACCiphertext, SK *SK, VKey *VKey, Key *Key, ct []byte) (string, error) {
	p := MPK.Order
	ASet := make(map[int]*bn256.GT)
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
	A, err := LSSS.ReconGT(CT.MSP, ASet, p)
	if err != nil {
		log.Fatalf("Fail to execute LSSSRecon ,Error: %v", err)
	}
	A = new(bn256.GT).Add(bn256.Pair(SK.K, CT._C), new(bn256.GT).Neg(A))
	K := new(bn256.GT).Add(CT.C, new(bn256.GT).Neg(A))
	_K := new(bn256.GT).Add(VKey.V1, new(bn256.GT).Neg(new(bn256.GT).ScalarMult(VKey.V0, Key.SK)))
	temp := make([]byte, len(ct))
	subtle.XORBytes(temp, ct, PRG(K, len(ct)))
	_Mes := make([]byte, len(ct))
	subtle.XORBytes(_Mes, temp, PRG(_K, len(ct)))
	return string(_Mes), nil
}
