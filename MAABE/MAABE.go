// LW MA-ABE
package MAABE

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
	"time"

	//"github.com/WXY1313/Trade/SymEnc"
	"github.com/WXY1313/Trade/SymEnc"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"golang.org/x/crypto/sha3"
)

func RandomInt() *big.Int {
	v, _ := data.NewRandomVector(1, sample.NewUniform(bn256.Order))
	return v[0]
}

func (a *MAABEKey) String() string {
	res := ""
	res += a.Gid
	res += a.Attr
	res += a.EK1.String()
	res += a.EK2.String()
	return res
}

func Hash(str string) *big.Int {
	hash := sha256.New()
	hash.Write([]byte(str))
	hashBytes := hash.Sum(nil)
	hashInt := new(big.Int).SetBytes(hashBytes)
	return hashInt
}

func (abe *MAABE) HashG1(pp *PP, msg string) *bn256.G1 {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(msg))
	v := hash.Sum(nil)
	return new(bn256.G1).ScalarMult(pp.G1, new(big.Int).SetBytes(v))
}

func (abe *MAABE) HashG2(pp *PP, msg string) *bn256.G2 {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(msg))
	v := hash.Sum(nil)
	return new(bn256.G2).ScalarMult(pp.G2, new(big.Int).SetBytes(v))
}

// MAABE represents a MAABE scheme.
type MAABE struct {
	P *big.Int
}

func NewMAABE() *MAABE {
	return &MAABE{P: bn256.Order}
}

// MAABE represents a MAABE scheme.
type PP struct {
	P  *big.Int
	G1 *bn256.G1
	G2 *bn256.G2
	GT *bn256.GT
}

// NewMAABE configures a new instance of the scheme.
func (maabe *MAABE) GlobalSetup() *PP {
	gen1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	gen2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	return &PP{
		P:  bn256.Order,
		G1: gen1,
		G2: gen2,
		GT: bn256.Pair(gen1, gen2),
	}
}

// MAABEPubKey represents a public key for an authority.
type MAABEPubKey struct {
	//Attribs    []string
	ID      string
	AlphaGT *bn256.GT
	BetaG1  *bn256.G1
	//AlphaG1 *bn256.G1
	//AlphaG2 *bn256.G2
}

// MAABESecKey represents a secret key for an authority.
type MAABESecKey struct {
	//Attribs []string
	Alpha *big.Int
	Beta  *big.Int
}

// MAABEAuth represents an authority in the MAABE scheme.
type MAABEAuth struct {
	//ID    string
	//Maabe *MAABE
	PK *MAABEPubKey
	SK *MAABESecKey
}

// NewMAABEAuth configures a new instance of an authority and generates its
// public and secret keys for the given set of attributes. In case of a failed
// procedure an error is returned.
func (maabe *MAABE) AuthSetup(pp *PP, id string) (*MAABEAuth, error) {
	//v, _ := data.NewRandomVector(2, sample.NewUniform(a.P))
	alpha := RandomInt()
	beta := RandomInt()
	sk := &MAABESecKey{Alpha: alpha, Beta: beta}
	//todo check GTOAlpha G2TOAlpha
	pk := &MAABEPubKey{ID: id, AlphaGT: new(bn256.GT).ScalarMult(pp.GT, alpha), BetaG1: new(bn256.G1).ScalarMult(pp.G1, beta)}
	return &MAABEAuth{
		//ID:    id,
		PK: pk,
		SK: sk,
	}, nil
}

// MAABECipher represents a ciphertext of a MAABE scheme.
type MAABECipher struct {
	C0         *bn256.GT
	C1x        map[string]*bn256.GT
	C2x        map[string]*bn256.G1
	C3x        map[string]*bn256.G1
	C4x        map[string]*bn256.G1
	Msp        *abe.MSP
	Ciphertext []byte // symmetric encryption of the string message
}

func (a *MAABECipher) String() string {
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

func (maabe *MAABE) Encrypt(pp *PP, msg string, msp *abe.MSP, pks []*MAABEPubKey) (*MAABECipher, error) {
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
	sampler := sample.NewUniform(maabe.P)
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
	startts := time.Now().UnixNano() / 1e3
	// calculate ciphertext
	c0 := new(bn256.GT).Add(symKey, new(bn256.GT).ScalarMult(pp.GT, s))
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
				F_delta := maabe.HashG1(pp, at)
				c4[at] = new(bn256.G1).ScalarMult(F_delta, r[at])
				foundPK = true
				break
			}
		}
		if !foundPK {
			return nil, fmt.Errorf("attribute not found in any pubkey")
		}
	}
	endts := time.Now().UnixNano() / 1e3
	if startts == endts {
		fmt.Printf("encrypt time cost: %v μs\n", (endts - startts))
	}

	return &MAABECipher{
		C0:         c0,
		C1x:        c1,
		C2x:        c2,
		C3x:        c3,
		C4x:        c4,
		Msp:        msp,
		Ciphertext: ciphertext,
	}, nil
}

// MAABEKey represents a key corresponding to an attribute possessed by an
// entity. They are issued by the relevant authorities and are used for
// decryption in a MAABE scheme.
type MAABEKey struct {
	Gid  string
	Attr string
	EK1  *bn256.G2
	EK2  *bn256.G2
	D    *big.Int
}

// ABEKeygen generates a key for the given attribute
func (maabe *MAABE) KeyGen(pp *PP, gid string, auth *MAABEAuth, at string, params ...interface{}) (*MAABEKey, error) {
	var alpha, beta, d = auth.SK.Alpha, auth.SK.Beta, RandomInt()
	var pt = pp.G2 //new(bn256.G1).Set(auth.Maabe.G1)
	if params != nil && len(params) == 1 {
		pt = params[0].(*bn256.G2)
	} else if params != nil && len(params) == 4 {
		pt = params[0].(*bn256.G2)
		alpha, beta, d = params[1].(*big.Int), params[2].(*big.Int), params[3].(*big.Int)
	}
	// sanity checks
	if len(gid) == 0 {
		return nil, fmt.Errorf("GID cannot be empty")
	}
	if maabe == nil {
		return nil, fmt.Errorf("ma-abe scheme cannot be nil")
	}
	hash := maabe.HashG2(pp, gid)

	ks := new(MAABEKey)
	//for i, at := range attribs {
	var ek1 *bn256.G2
	var ek2 *bn256.G2
	if strings.Split(at, ":")[0] != auth.PK.ID {
		return nil, fmt.Errorf("the attribute does not belong to the authority")
	}
	F_delta := maabe.HashG2(pp, at)
	ek1 = new(bn256.G2).Add(new(bn256.G2).ScalarMult(pt, alpha), new(bn256.G2).ScalarMult(hash, beta))
	ek1 = new(bn256.G2).Add(ek1, new(bn256.G2).ScalarMult(F_delta, d))
	ek2 = new(bn256.G2).ScalarMult(pp.G2, d)
	ks = &MAABEKey{
		Gid:  gid,
		Attr: at,
		EK1:  ek1,
		EK2:  ek2,
		D:    d,
	}
	return ks, nil
}

// ABEDecrypt takes a ciphertext in a MAABE scheme and a set of attribute keys
// belonging to the same entity, and attempts to decrypt the cipher. This is
// possible only if the set of possessed attributes/keys suffices the
// decryption policy of the ciphertext. In case this is not possible or
// something goes wrong an error is returned.
func (a *MAABE) Decrypt(pp *PP, ct *MAABECipher, ks []*MAABEKey) (string, error) {
	// sanity checks
	if len(ks) == 0 {
		return "", fmt.Errorf("empty set of attribute keys")
	}
	gid := ks[0].Gid
	for _, k := range ks {
		if k.Gid != gid {
			return "", fmt.Errorf("not all GIDs are the same")
		}
	}
	// get hashed GID
	hash := a.HashG2(pp, gid)
	//if err != nil {
	//	return "", err
	//}
	// find out which attributes are valid and extract them
	goodMatRows := make([]data.Vector, 0)
	goodAttribs := make([]string, 0)
	aToK := make(map[string]*MAABEKey)
	for _, k := range ks {
		aToK[k.Attr] = k
	}
	for i, at := range ct.Msp.RowToAttrib {
		if aToK[at] != nil {
			goodMatRows = append(goodMatRows, ct.Msp.Mat[i])
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
	c, err := data.GaussianEliminationSolver(goodMat.Transpose(), one, a.P)
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
		if ct.C1x[at] != nil && ct.C2x[at] != nil && ct.C3x[at] != nil && ct.C4x[at] != nil {
			num := new(bn256.GT).Add(ct.C1x[at], bn256.Pair(ct.C2x[at], aToK[at].EK1))
			num = new(bn256.GT).Add(num, bn256.Pair(ct.C3x[at], hash))
			num = new(bn256.GT).Add(num, bn256.Pair(ct.C4x[at], aToK[at].EK2))
			eggLambda[at] = num
		} else {
			fmt.Println(ct.C1x[at] != nil, ct.C2x[at] != nil, ct.C3x[at] != nil, ct.C4x[at] != nil)
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
	symKey := new(bn256.GT).Add(ct.C0, new(bn256.GT).Neg(eggs))
	msg := SymEnc.XOREncryptDecrypt(ct.Ciphertext, SymEnc.KDF(symKey))
	fmt.Println(string(msg))
	return string(msg), nil
}
