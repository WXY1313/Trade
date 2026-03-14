package PREMAABE

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"

	"github.com/WXY1313/Trade/Crypto/SymEnc"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"golang.org/x/crypto/sha3"
)

// MAABE represents a MAABE scheme.
type PREMAABE struct {
	P *big.Int
}

func NewPREMAABE() *PREMAABE {
	return &PREMAABE{P: bn256.Order}
}

func RandomInt() *big.Int {
	v, _ := data.NewRandomVector(1, sample.NewUniform(bn256.Order))
	return v[0]
}

func HashG1(pp *PP, msg string) *bn256.G1 {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(msg))
	v := hash.Sum(nil)
	return new(bn256.G1).ScalarMult(pp.G1, new(big.Int).SetBytes(v))
}

func HashG2(pp *PP, msg string) *bn256.G2 {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(msg))
	v := hash.Sum(nil)
	return new(bn256.G2).ScalarMult(pp.G2, new(big.Int).SetBytes(v))
}

func HashGTToBigInt(gt *bn256.GT) *big.Int {

	gtBytes := gt.Marshal()

	hash := sha256.New()
	hash.Write(gtBytes)
	hashBytes := hash.Sum(nil)
	result := new(big.Int).SetBytes(hashBytes)
	return result
}

// MAABE represents a MAABE scheme.
type PP struct {
	P  *big.Int
	G1 *bn256.G1
	G2 *bn256.G2
	GT *bn256.GT
}

// NewMAABE configures a new instance of the scheme.
func (maabe *PREMAABE) GlobalSetup() *PP {
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	return &PP{
		P:  bn256.Order,
		G1: g1,
		G2: g2,
		GT: bn256.Pair(g1, g2),
	}
}

type AuthPK struct {
	//Attribs    []string
	ID      string
	AlphaGT *bn256.GT
	BetaG1  *bn256.G1
	//AlphaG1 *bn256.G1
	//AlphaG2 *bn256.G2
}

// MAABESecKey represents a secret key for an authority.
type AuthSK struct {
	//Attribs []string
	Alpha *big.Int
	Beta  *big.Int
}

// MAABEAuth represents an authority in the MAABE scheme.
type Auth struct {
	//ID    string
	//Maabe *MAABE
	PK *AuthPK
	SK *AuthSK
}

// NewMAABEAuth configures a new instance of an authority and generates its
// public and secret keys for the given set of attributes. In case of a failed
// procedure an error is returned.
func AuthSetup(pp *PP, id string) (*Auth, error) {
	//v, _ := data.NewRandomVector(2, sample.NewUniform(a.P))
	alpha := RandomInt()
	beta := RandomInt()
	sk := &AuthSK{Alpha: alpha, Beta: beta}
	//todo check GTOAlpha G2TOAlpha
	pk := &AuthPK{ID: id, AlphaGT: new(bn256.GT).ScalarMult(pp.GT, alpha), BetaG1: new(bn256.G1).ScalarMult(pp.G1, beta)}
	return &Auth{
		//ID:    id,
		PK: pk,
		SK: sk,
	}, nil
}

// MAABEKey represents a key corresponding to an attribute possessed by an
// entity. They are issued by the relevant authorities and are used for
// decryption in a MAABE scheme.
type AttrKey struct {
	Gid  string
	Attr string
	EK1  *bn256.G2
	EK2  *bn256.G2
	D    *big.Int
}

// ABEKeygen generates a key for the given attribute
func KeyGen(pp *PP, gid string, auth *Auth, at string) (*AttrKey, error) {
	var alpha, beta, d = auth.SK.Alpha, auth.SK.Beta, RandomInt()
	var pt = pp.G2 //new(bn256.G1).Set(auth.Maabe.G1)

	// sanity checks
	if len(gid) == 0 {
		return nil, fmt.Errorf("GID cannot be empty")
	}

	hash := HashG2(pp, gid)

	ks := new(AttrKey)
	//for i, at := range attribs {
	var ek1 *bn256.G2
	var ek2 *bn256.G2
	if strings.Split(at, ":")[0] != auth.PK.ID {
		return nil, fmt.Errorf("the attribute does not belong to the authority")
	}
	F_delta := HashG2(pp, at)
	ek1 = new(bn256.G2).Add(new(bn256.G2).ScalarMult(pt, alpha), new(bn256.G2).ScalarMult(hash, beta))
	ek1 = new(bn256.G2).Add(ek1, new(bn256.G2).ScalarMult(F_delta, d))
	ek2 = new(bn256.G2).ScalarMult(pp.G2, d)
	ks = &AttrKey{
		Gid:  gid,
		Attr: at,
		EK1:  ek1,
		EK2:  ek2,
		D:    d,
	}
	return ks, nil
}

type ReKey struct {
	Attr []string
	Gid  string
	RK1  *big.Int
	RK2  *bn256.G1
	RK3  []*bn256.G2
	RK4  []*bn256.G2
}

func ReKeyGen(gid string, akSet []*AttrKey) (*bn256.GT, *ReKey, error) {

	var attrSet []string
	var rk3 []*bn256.G2
	var rk4 []*bn256.G2

	_, X, err := bn256.RandomGT(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	rk1 := HashGTToBigInt(X)
	z, rk2, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < len(akSet); i++ {
		attrSet = append(attrSet, akSet[i].Attr)
		rk3 = append(rk3, new(bn256.G2).Add(new(bn256.G2).ScalarMult(akSet[i].EK1, rk1), new(bn256.G2).ScalarBaseMult(z)))
		rk4 = append(rk4, new(bn256.G2).ScalarMult(akSet[i].EK2, rk1))
	}

	return X, &ReKey{
		Gid:  gid,
		Attr: attrSet,
		RK1:  rk1,
		RK2:  rk2,
		RK3:  rk3,
		RK4:  rk4,
	}, nil
}

type EDK struct {
	C0  *bn256.GT
	C1x map[string]*bn256.GT
	C2x map[string]*bn256.G1
	C3x map[string]*bn256.G1
	C4x map[string]*bn256.G1
	Msp *abe.MSP
}

func EDKGen(pp *PP, X *bn256.GT, msp *abe.MSP, pks []*AuthPK) (*EDK, error) {
	// sanity checks
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}
	mspRows := msp.Mat.Rows()
	mspCols := msp.Mat.Cols()
	attribs := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if attribs[i] {
			return nil, fmt.Errorf("some attributes correspond to" +
				"multiple rows of the MSP struct, the scheme is not secure")
		}
		attribs[i] = true
	}

	// now encrypt symKey with MA-ABE
	// rand generator
	sampler := sample.NewUniform(bn256.Order)
	// pick random vector v with random s as first element
	v, err := data.NewRandomVector(mspCols, sampler)
	if err != nil {
		return nil, err
	}
	s := v[0]
	if err != nil {
		return nil, err
	}
	lambdaI, err := msp.Mat.MulVec(v)
	if err != nil {
		return nil, err
	}
	if len(lambdaI) != mspRows {
		return nil, fmt.Errorf("wrong lambda len")
	}
	lambda := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		lambda[at] = lambdaI[i]
	}
	// pick random vector w with 0 as first element
	w, err := data.NewRandomVector(mspCols, sampler)
	if err != nil {
		return nil, err
	}
	w[0] = big.NewInt(0)
	omegaI, err := msp.Mat.MulVec(w)
	if err != nil {
		return nil, err
	}
	if len(omegaI) != mspRows {
		return nil, fmt.Errorf("wrong omega len")
	}
	omega := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		omega[at] = omegaI[i]
	}

	// calculate ciphertext
	c0 := new(bn256.GT).Add(X, new(bn256.GT).ScalarMult(pp.GT, s))
	c1 := make(map[string]*bn256.GT)
	c2 := make(map[string]*bn256.G1)
	c3 := make(map[string]*bn256.G1)
	c4 := make(map[string]*bn256.G1)
	// get randomness
	rI, err := data.NewRandomVector(mspRows, sampler)
	r := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		r[at] = rI[i]
	}
	if err != nil {
		return nil, err
	}
	for _, at := range msp.RowToAttrib {
		// find the correct pubkey
		foundPK := false
		for _, pk := range pks {
			if strings.Split(at, ":")[0] == pk.ID {
				// CAREFUL: negative numbers do not play well with ScalarMult
				signLambda := lambda[at].Cmp(big.NewInt(0))
				signOmega := omega[at].Cmp(big.NewInt(0))
				var tmpLambda *bn256.GT
				var tmpOmega *bn256.G1
				if signLambda >= 0 {
					tmpLambda = new(bn256.GT).ScalarMult(pp.GT, lambda[at])
				} else {
					tmpLambda = new(bn256.GT).ScalarMult(new(bn256.GT).Neg(pp.GT), new(big.Int).Abs(lambda[at]))
				}
				if signOmega >= 0 {
					tmpOmega = new(bn256.G1).ScalarMult(pp.G1, omega[at])
				} else {
					tmpOmega = new(bn256.G1).ScalarMult(new(bn256.G1).Neg(pp.G1), new(big.Int).Abs(omega[at]))
				}
				c1[at] = new(bn256.GT).Add(tmpLambda, new(bn256.GT).ScalarMult(pk.AlphaGT, r[at]))
				c2[at] = new(bn256.G1).ScalarMult(new(bn256.G1).Neg(pp.G1), r[at]) //new(bn256.G2).ScalarMult(a.G2, r[at])
				c3[at] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(pk.BetaG1, r[at]), tmpOmega)
				F_delta := HashG1(pp, at)
				c4[at] = new(bn256.G1).ScalarMult(F_delta, r[at])
				foundPK = true
				break
			}
		}
		if !foundPK {
			return nil, fmt.Errorf("attribute not found in any pubkey")
		}
	}

	return &EDK{
		C0:  c0,
		C1x: c1,
		C2x: c2,
		C3x: c3,
		C4x: c4,
		Msp: msp,
	}, nil

}

// MAABECipher represents a ciphertext of a MAABE scheme.
type Cipher struct {
	C0         *bn256.GT
	C1x        map[string]*bn256.GT
	C2x        map[string]*bn256.G1
	C3x        map[string]*bn256.G1
	C4x        map[string]*bn256.G1
	C5x        map[string]*bn256.G2
	Msp        *abe.MSP
	Ciphertext []byte // symmetric encryption of the string message
}

func (a *Cipher) String() string {
	res := ""
	res += a.C0.String()
	for one := range a.C1x {
		res += a.C1x[one].String()
		res += a.C2x[one].String()
		res += a.C3x[one].String()
		res += a.C4x[one].String()
	}

	return res
}

func Encrypt(pp *PP, msg string, msp *abe.MSP, pks []*AuthPK) (*Cipher, error) {
	// sanity checks
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}
	mspRows := msp.Mat.Rows()
	mspCols := msp.Mat.Cols()
	attribs := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if attribs[i] {
			return nil, fmt.Errorf("some attributes correspond to" +
				"multiple rows of the MSP struct, the scheme is not secure")
		}
		attribs[i] = true
	}
	if len(msg) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}
	// msg is encrypted with AES-CBC with a random key that is encrypted with
	// MA-ABE
	// generate secret key
	_, symKey, err := bn256.RandomGT(rand.Reader)
	//fmt.Println(symKey)
	if err != nil {
		return nil, err
	}
	ciphertext := SymEnc.XOREncryptDecrypt([]byte(msg), SymEnc.KDF(symKey))

	// now encrypt symKey with MA-ABE
	// rand generator
	sampler := sample.NewUniform(bn256.Order)
	// pick random vector v with random s as first element
	v, err := data.NewRandomVector(mspCols, sampler)
	if err != nil {
		return nil, err
	}
	s := v[0]
	if err != nil {
		return nil, err
	}
	lambdaI, err := msp.Mat.MulVec(v)
	if err != nil {
		return nil, err
	}
	if len(lambdaI) != mspRows {
		return nil, fmt.Errorf("wrong lambda len")
	}
	lambda := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		lambda[at] = lambdaI[i]
	}
	// pick random vector w with 0 as first element
	w, err := data.NewRandomVector(mspCols, sampler)
	if err != nil {
		return nil, err
	}
	w[0] = big.NewInt(0)
	omegaI, err := msp.Mat.MulVec(w)
	if err != nil {
		return nil, err
	}
	if len(omegaI) != mspRows {
		return nil, fmt.Errorf("wrong omega len")
	}
	omega := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		omega[at] = omegaI[i]
	}

	// calculate ciphertext
	c0 := new(bn256.GT).Add(symKey, new(bn256.GT).ScalarMult(pp.GT, s))
	c1 := make(map[string]*bn256.GT)
	c2 := make(map[string]*bn256.G1)
	c3 := make(map[string]*bn256.G1)
	c4 := make(map[string]*bn256.G1)
	c5 := make(map[string]*bn256.G2)
	// get randomness
	rI, err := data.NewRandomVector(mspRows, sampler)
	r := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		r[at] = rI[i]
	}
	if err != nil {
		return nil, err
	}
	for _, at := range msp.RowToAttrib {
		// find the correct pubkey
		foundPK := false
		for _, pk := range pks {
			if strings.Split(at, ":")[0] == pk.ID {
				// CAREFUL: negative numbers do not play well with ScalarMult
				signLambda := lambda[at].Cmp(big.NewInt(0))
				signOmega := omega[at].Cmp(big.NewInt(0))
				var tmpLambda *bn256.GT
				var tmpOmega *bn256.G1
				if signLambda >= 0 {
					tmpLambda = new(bn256.GT).ScalarMult(pp.GT, lambda[at])
				} else {
					tmpLambda = new(bn256.GT).ScalarMult(new(bn256.GT).Neg(pp.GT), new(big.Int).Abs(lambda[at]))
				}
				if signOmega >= 0 {
					tmpOmega = new(bn256.G1).ScalarMult(pp.G1, omega[at])
				} else {
					tmpOmega = new(bn256.G1).ScalarMult(new(bn256.G1).Neg(pp.G1), new(big.Int).Abs(omega[at]))
				}
				c1[at] = new(bn256.GT).Add(tmpLambda, new(bn256.GT).ScalarMult(pk.AlphaGT, r[at]))
				c2[at] = new(bn256.G1).ScalarMult(new(bn256.G1).Neg(pp.G1), r[at]) //new(bn256.G2).ScalarMult(a.G2, r[at])
				c3[at] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(pk.BetaG1, r[at]), tmpOmega)
				F_delta := HashG1(pp, at)
				c4[at] = new(bn256.G1).ScalarMult(F_delta, r[at])
				c5[at] = new(bn256.G2).ScalarMult(new(bn256.G2).Neg(pp.G2), r[at])
				foundPK = true
				break
			}
		}
		if !foundPK {
			return nil, fmt.Errorf("attribute not found in any pubkey")
		}
	}

	return &Cipher{
		C0:         c0,
		C1x:        c1,
		C2x:        c2,
		C3x:        c3,
		C4x:        c4,
		C5x:        c5,
		Msp:        msp,
		Ciphertext: ciphertext,
	}, nil
}

type ReCipher struct {
	RC1        *bn256.GT
	RC2        *bn256.GT
	Ciphertext []byte
}

func ReEncrypt(pp *PP, rk *ReKey, ct *Cipher) (*ReCipher, error) {
	// sanity checks
	if len(rk.Attr) == 0 {
		return nil, fmt.Errorf("empty set of attribute keys")
	}
	gid := rk.Gid

	// get hashed GID
	hash := HashG2(pp, gid)
	//if err != nil {
	//	return "", err
	//}
	// find out which attributes are valid and extract them
	goodMatRows := make([]data.Vector, 0)
	goodAttribs := make([]string, 0)

	aToK := make(map[string]*AttrKey)
	for i := 0; i < len(rk.Attr); i++ {
		attrName := rk.Attr[i]
		if aToK[attrName] == nil {
			aToK[attrName] = &AttrKey{}
		}
		aToK[attrName].EK1 = rk.RK3[i]
		aToK[attrName].EK2 = rk.RK4[i]
	}
	for i, at := range ct.Msp.RowToAttrib {
		if aToK[at] != nil {
			goodMatRows = append(goodMatRows, ct.Msp.Mat[i])
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
		if ct.C1x[at] != nil && ct.C2x[at] != nil && ct.C3x[at] != nil && ct.C4x[at] != nil {
			numUp := new(bn256.GT).Add(new(bn256.GT).ScalarMult(ct.C1x[at], rk.RK1), bn256.Pair(ct.C2x[at], aToK[at].EK1))
			numUp = new(bn256.GT).Add(numUp, bn256.Pair(new(bn256.G1).ScalarMult(ct.C3x[at], rk.RK1), hash))
			numBottom := bn256.Pair(new(bn256.G1).Neg(ct.C4x[at]), aToK[at].EK2)
			numBottom = new(bn256.GT).Add(numBottom, bn256.Pair(rk.RK2, ct.C5x[at]))
			eggLambda[at] = new(bn256.GT).Add(numUp, new(bn256.GT).Neg(numBottom))
		} else {
			fmt.Println(ct.C1x[at] != nil, ct.C2x[at] != nil, ct.C3x[at] != nil, ct.C4x[at] != nil)
			return nil, fmt.Errorf("attribute %s not in ciphertext dicts", at)
		}
	}
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
	// calculate key for symmetric encryption
	rc1 := eggs
	rc2 := ct.C0
	ciphertext := ct.Ciphertext
	return &ReCipher{RC1: rc1, RC2: rc2, Ciphertext: ciphertext}, nil
}

func ReDecrypt(pp *PP, ak []*AttrKey, edk *EDK, recipher *ReCipher) (string, error) {
	// sanity checks
	if len(ak) == 0 {
		return "", fmt.Errorf("empty set of attribute keys")
	}
	gid := ak[0].Gid
	for _, k := range ak {
		if k.Gid != gid {
			return "", fmt.Errorf("not all GIDs are the same")
		}
	}
	// get hashed GID
	hash := HashG2(pp, gid)
	//if err != nil {
	//	return "", err
	//}
	// find out which attributes are valid and extract them
	goodMatRows := make([]data.Vector, 0)
	goodAttribs := make([]string, 0)
	aToK := make(map[string]*AttrKey)
	for _, k := range ak {
		aToK[k.Attr] = k
	}
	for i, at := range edk.Msp.RowToAttrib {
		if aToK[at] != nil {
			goodMatRows = append(goodMatRows, edk.Msp.Mat[i])
			goodAttribs = append(goodAttribs, at)
		}
	}
	goodMat, err := data.NewMatrix(goodMatRows)
	if err != nil {
		return "", err
	}
	//choose consts c_x, such that \sum c_x A_x = (1,0,...,0)
	// if they don't exist, keys are not ok
	goodCols := goodMat.Cols()
	if goodCols == 0 {
		return "", fmt.Errorf("no good matrix columns, most likely the keys contain no valid attribute")
	}
	one := data.NewConstantVector(goodCols, big.NewInt(0))
	one[0] = big.NewInt(1)
	c, err := data.GaussianEliminationSolver(goodMat.Transpose(), one, bn256.Order)
	if err != nil {
		return "", err
	}
	cx := make(map[string]*big.Int)
	for i, at := range goodAttribs {
		cx[at] = c[i]
	}
	// compute intermediate values
	eggLambda := make(map[string]*bn256.GT)
	for _, at := range goodAttribs {
		if edk.C1x[at] != nil && edk.C2x[at] != nil && edk.C3x[at] != nil && edk.C4x[at] != nil {
			num := new(bn256.GT).Add(edk.C1x[at], bn256.Pair(edk.C2x[at], aToK[at].EK1))
			num = new(bn256.GT).Add(num, bn256.Pair(edk.C3x[at], hash))
			num = new(bn256.GT).Add(num, bn256.Pair(edk.C4x[at], aToK[at].EK2))
			eggLambda[at] = num
		} else {
			fmt.Println(edk.C1x[at] != nil, edk.C2x[at] != nil, edk.C3x[at] != nil, edk.C4x[at] != nil)
			return "", fmt.Errorf("attribute %s not in ciphertext dicts", at)
		}
	}
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
			return "", fmt.Errorf("missing intermediate result")
		}
	}
	// calculate key for symmetric encryption
	Delta := new(bn256.GT).Add(edk.C0, new(bn256.GT).Neg(eggs))
	hash1 := HashGTToBigInt(Delta)
	hashInv := new(big.Int).ModInverse(hash1, bn256.Order)
	if hashInv == nil {
		return "", fmt.Errorf("failed to compute modular inverse for H1 hash")
	}
	symKey := new(bn256.GT).Add(recipher.RC2, new(bn256.GT).Neg(new(bn256.GT).ScalarMult(recipher.RC1, hashInv)))
	msg := SymEnc.XOREncryptDecrypt(recipher.Ciphertext, SymEnc.KDF(symKey))
	fmt.Println(string(msg))
	return string(msg), nil
}
