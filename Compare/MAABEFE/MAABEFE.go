package MAABEFE

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
	"sort"
	"strings"

	"github.com/WXY1313/Trade/Crypto/Operation"
	"github.com/WXY1313/Trade/Crypto/SymEnc"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	lib "github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"golang.org/x/crypto/sha3"
)

type MAABEFE struct {
	P *big.Int
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

func writeMapGT(h hash.Hash, m map[string]*bn256.GT) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		h.Write(m[k].Marshal())
	}
}

func writeMapG1(h hash.Hash, m map[string]*bn256.G1) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		h.Write(m[k].Marshal())
	}
}

func G1ArrayToBigInt(cm *CM, _cm *CM, _dm *bn256.G1) *big.Int {

	h := sha256.New()

	h.Write(cm.C0.Marshal())
	h.Write(cm.C5.Marshal())

	writeMapGT(h, cm.C1x)
	writeMapG1(h, cm.C2x)
	writeMapG1(h, cm.C3x)
	writeMapG1(h, cm.C4x)

	h.Write(_cm.C0.Marshal())
	h.Write(_cm.C5.Marshal())

	writeMapGT(h, _cm.C1x)
	writeMapG1(h, _cm.C2x)
	writeMapG1(h, _cm.C3x)
	writeMapG1(h, _cm.C4x)

	h.Write(_dm.Marshal())

	x := new(big.Int).SetBytes(h.Sum(nil))
	return x.Mod(x, bn256.Order)
}

func LSSSRecon(msp *lib.MSP, idToShare map[string]*big.Int) (*big.Int, error) {
	goodMatRows := make([]data.Vector, 0)
	goodHolders := make([]string, 0)

	for i, id := range msp.RowToAttrib {
		if idToShare[id] != nil {
			goodMatRows = append(goodMatRows, msp.Mat[i])
			goodHolders = append(goodHolders, id)
		}
	}
	goodMat, err := data.NewMatrix(goodMatRows)
	if err != nil {
		return nil, err
	}

	//choose consts c_x, such that \sum c_x A_x = (1,0,...,0)
	// if they don't exist, holders are not ok
	goodCols := goodMat.Cols()
	if goodCols == 0 {
		return nil, fmt.Errorf("no good matrix columns")
	}
	one := data.NewConstantVector(goodCols, big.NewInt(0))
	one[0] = big.NewInt(1)
	c, err := data.GaussianEliminationSolver(goodMat.Transpose(), one, bn256.Order)
	if err != nil {
		return nil, err
	}
	s := big.NewInt(0)
	for i, id := range goodHolders {
		s.Add(s, new(big.Int).Mul(c[i], idToShare[id]))
	}
	s.Mod(s, bn256.Order)
	return s, nil
}

// MAABE represents a MAABE scheme.
type PP struct {
	P  *big.Int
	G1 *bn256.G1
	H1 *bn256.G1
	H2 *bn256.G2
	G2 *bn256.G2
	GT *bn256.GT
}

// NewMAABE configures a new instance of the scheme.
func GlobalSetup() *PP {
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	hScalar, _ := new(big.Int).SetString("9868996996480530350723936346388037348513707152826932716320380442065450531909", 10)
	h1 := new(bn256.G1).ScalarBaseMult(hScalar)
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	h2 := new(bn256.G2).ScalarBaseMult(hScalar)
	return &PP{
		P:  bn256.Order,
		G1: g1,
		H1: h1,
		H2: h2,
		G2: g2,
		GT: bn256.Pair(g1, g2),
	}
}

// MAABEPubKey represents a public key for an authority.
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
	PK *AuthPK
	SK *AuthSK
}

// NewMAABEAuth configures a new instance of an authority and generates its
// public and secret keys for the given set of attributes. In case of a failed
// procedure an error is returned.
func AuthSetup(pp *PP, id string) (*Auth, error) {
	//v, _ := data.NewRandomVector(2, sample.NewUniform(a.P))
	alpha := Operation.RandomInt()
	beta := Operation.RandomInt()
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
	var alpha, beta, d = auth.SK.Alpha, auth.SK.Beta, Operation.RandomInt()
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

// MAABECipher represents a ciphertext of a MAABE scheme.
type CM struct {
	C0  *bn256.G1
	C1x map[string]*bn256.GT
	C2x map[string]*bn256.G1
	C3x map[string]*bn256.G1
	C4x map[string]*bn256.G1
	C5  *bn256.G1
}

type Cipher struct {
	CM         *CM
	DM         *bn256.G1
	Msp        *abe.MSP
	Ciphertext []byte // symmetric encryption of the string message
	SymKey     *bn256.GT
}

type NIZKCipher struct {
	CM     *CM
	DM     *bn256.G1
	M      *big.Int
	S      *big.Int
	R      map[string]*big.Int
	Lambda map[string]*big.Int
	Omega  map[string]*big.Int
}

func Encrypt(pp *PP, m *big.Int, msg string, msp *abe.MSP, pkSet []*AuthPK) (*Cipher, *NIZKCipher, error) {
	sampler := sample.NewUniform(pp.P)
	// sanity checks
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, nil, fmt.Errorf("empty msp matrix")
	}
	mspRows := msp.Mat.Rows()
	mspCols := msp.Mat.Cols()
	attribs := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if attribs[i] {
			return nil, nil, fmt.Errorf("some attributes correspond to" +
				"multiple rows of the MSP struct, the scheme is not secure")
		}
		attribs[i] = true
	}
	if len(msg) == 0 {
		return nil, nil, fmt.Errorf("message cannot be empty")
	}
	// msg is encrypted with AES-CBC with a random key that is encrypted with
	// MA-ABE
	// generate secret key
	symKey := new(bn256.GT).ScalarBaseMult(m)
	ciphertext := SymEnc.XOREncryptDecrypt([]byte(msg), SymEnc.KDF(symKey))
	// now encrypt symKey with MA-ABE
	// rand generator

	// pick random vector v with random s as first element
	v, err := data.NewRandomVector(mspCols, sampler)
	if err != nil {
		return nil, nil, err
	}
	s := v[0]
	c5 := new(bn256.G1).ScalarMult(pp.H1, s)
	// if err != nil {
	// 	return nil, nil, err
	// }
	lambdaI, err := msp.Mat.MulVec(v)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// if len(lambdaI) != mspRows {
	// 	return nil, nil, fmt.Errorf("wrong lambda len")
	// }
	lambda := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		lambda[at] = lambdaI[i]
	}
	// pick random vector w with 0 as first element
	w, err := data.NewRandomVector(mspCols, sampler)
	// if err != nil {
	// 	return nil, nil, err
	// }
	w[0] = big.NewInt(0)
	omegaI, err := msp.Mat.MulVec(w)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// if len(omegaI) != mspRows {
	// 	return nil, nil, fmt.Errorf("wrong omega len")
	// }
	omega := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		omega[at] = omegaI[i]
	}
	// calculate ciphertext
	c0 := new(bn256.G1).Add(new(bn256.G1).ScalarBaseMult(m), new(bn256.G1).ScalarBaseMult(s))
	dm := new(bn256.G1).ScalarMult(pp.H1, m)
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
		return nil, nil, err
	}
	for _, at := range msp.RowToAttrib {
		// find the correct pubkey
		//foundPK := false
		for _, pk := range pkSet {
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
				//foundPK = true
				break
			}
		}
		// if !foundPK {
		// 	return nil, nil, fmt.Errorf("attribute not found in any pubkey")
		// }
	}

	cm := &CM{
		C0:  c0,
		C1x: c1,
		C2x: c2,
		C3x: c3,
		C4x: c4,
		C5:  c5,
	}

	Cipher := &Cipher{
		CM:         cm,
		Msp:        msp,
		Ciphertext: ciphertext,
		SymKey:     symKey,
		DM:         dm,
	}

	//Generate NIZK proof
	_m, _ := sampler.Sample()

	// pick random vector v with random s as first element
	_v, err := data.NewRandomVector(mspCols, sampler)
	// if err != nil {
	// 	return nil, nil, err
	// }
	_s := _v[0]
	_c5 := new(bn256.G1).ScalarMult(pp.H1, _s)
	// if err != nil {
	// 	return nil, nil, err
	// }
	_lambdaI, err := msp.Mat.MulVec(_v)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// if len(lambdaI) != mspRows {
	// 	return nil, nil, fmt.Errorf("wrong lambda len")
	// }
	_lambda := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		_lambda[at] = _lambdaI[i]
	}
	// pick random vector w with 0 as first element
	_w, err := data.NewRandomVector(mspCols, sampler)
	// if err != nil {
	// 	return nil, nil, err
	// }
	_w[0] = big.NewInt(0)
	_omegaI, err := msp.Mat.MulVec(_w)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// if len(_omegaI) != mspRows {
	// 	return nil, nil, fmt.Errorf("wrong omega len")
	// }
	_omega := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		_omega[at] = _omegaI[i]
	}
	// calculate ciphertext
	_c0 := new(bn256.G1).Add(new(bn256.G1).ScalarBaseMult(_m), new(bn256.G1).ScalarBaseMult(_s))
	_dm := new(bn256.G1).ScalarMult(pp.H1, _m)
	_c1 := make(map[string]*bn256.GT)
	_c2 := make(map[string]*bn256.G1)
	_c3 := make(map[string]*bn256.G1)
	_c4 := make(map[string]*bn256.G1)
	// get randomness
	_rI, err := data.NewRandomVector(mspRows, sampler)
	_r := make(map[string]*big.Int)
	for i, at := range msp.RowToAttrib {
		_r[at] = _rI[i]
	}
	// if err != nil {
	// 	return nil, nil, err
	// }
	for _, at := range msp.RowToAttrib {
		// find the correct pubkey
		//foundPK := false
		for _, pk := range pkSet {
			if strings.Split(at, ":")[0] == pk.ID {
				// CAREFUL: negative numbers do not play well with ScalarMult
				_signLambda := _lambda[at].Cmp(big.NewInt(0))
				_signOmega := _omega[at].Cmp(big.NewInt(0))
				var _tmpLambda *bn256.GT
				var _tmpOmega *bn256.G1
				if _signLambda >= 0 {
					_tmpLambda = new(bn256.GT).ScalarMult(pp.GT, _lambda[at])
				} else {
					_tmpLambda = new(bn256.GT).ScalarMult(new(bn256.GT).Neg(pp.GT), new(big.Int).Abs(_lambda[at]))
				}
				if _signOmega >= 0 {
					_tmpOmega = new(bn256.G1).ScalarMult(pp.G1, _omega[at])
				} else {
					_tmpOmega = new(bn256.G1).ScalarMult(new(bn256.G1).Neg(pp.G1), new(big.Int).Abs(_omega[at]))
				}
				_c1[at] = new(bn256.GT).Add(_tmpLambda, new(bn256.GT).ScalarMult(pk.AlphaGT, _r[at]))
				_c2[at] = new(bn256.G1).ScalarMult(new(bn256.G1).Neg(pp.G1), _r[at]) //new(bn256.G2).ScalarMult(a.G2, r[at])
				_c3[at] = new(bn256.G1).Add(new(bn256.G1).ScalarMult(pk.BetaG1, _r[at]), _tmpOmega)
				_F_delta := HashG1(pp, at)
				_c4[at] = new(bn256.G1).ScalarMult(_F_delta, _r[at])
				//foundPK = true
				break
			}
		}
		// if !foundPK {
		// 	return nil, nil, fmt.Errorf("attribute not found in any pubkey")
		// }
	}

	_cm := &CM{
		C0:  _c0,
		C1x: _c1,
		C2x: _c2,
		C3x: _c3,
		C4x: _c4,
		C5:  _c5,
	}

	challenge := G1ArrayToBigInt(cm, _cm, _dm)
	Res_m := new(big.Int).Sub(_m, new(big.Int).Mul(challenge, m))
	Res_m = Res_m.Mod(Res_m, bn256.Order)
	Res_s := new(big.Int).Sub(_s, new(big.Int).Mul(challenge, s))
	Res_s = Res_s.Mod(Res_s, bn256.Order)
	for _, at := range msp.RowToAttrib {
		_r[at] = new(big.Int).Sub(_r[at], new(big.Int).Mul(challenge, r[at]))
		_r[at] = _r[at].Mod(_r[at], bn256.Order)
		_lambda[at] = new(big.Int).Sub(_lambda[at], new(big.Int).Mul(challenge, lambda[at]))
		_lambda[at] = _lambda[at].Mod(_lambda[at], bn256.Order)
		_omega[at] = new(big.Int).Sub(_omega[at], new(big.Int).Mul(challenge, omega[at]))
		_omega[at] = _omega[at].Mod(_omega[at], bn256.Order)
	}

	NIZKCipher := &NIZKCipher{
		CM:     _cm,
		DM:     _dm,
		M:      Res_m,
		S:      Res_s,
		R:      _r,
		Lambda: _lambda,
		Omega:  _omega,
	}

	return Cipher, NIZKCipher, nil
}

func CheckCipher(pp *PP, cipher *Cipher, cipherNIZK *NIZKCipher, pkSet []*AuthPK) bool {
	challenge := G1ArrayToBigInt(cipher.CM, cipherNIZK.CM, cipherNIZK.DM)
	fmt.Printf("Challenge=%v\n", challenge)
	if !Operation.G1Equal(cipherNIZK.CM.C0, new(bn256.G1).Add(new(bn256.G1).Add(new(bn256.G1).ScalarBaseMult(cipherNIZK.S), new(bn256.G1).ScalarBaseMult(cipherNIZK.M)), new(bn256.G1).ScalarMult(cipher.CM.C0, challenge))) {
		return false
	}
	if !Operation.G1Equal(cipherNIZK.CM.C5, new(bn256.G1).Add(new(bn256.G1).ScalarMult(pp.H1, cipherNIZK.S), new(bn256.G1).ScalarMult(cipher.CM.C5, challenge))) {
		return false
	}
	if !Operation.G1Equal(cipherNIZK.DM, new(bn256.G1).Add(new(bn256.G1).ScalarMult(pp.H1, cipherNIZK.M), new(bn256.G1).ScalarMult(cipher.DM, challenge))) {
		return false
	}
	if !Operation.GTEqual(bn256.Pair(cipher.CM.C0, pp.H2), bn256.Pair(new(bn256.G1).Add(cipher.CM.C5, cipher.DM), pp.G2)) {
		return false
	}
	for _, at := range cipher.Msp.RowToAttrib {
		for _, pk := range pkSet {
			if strings.Split(at, ":")[0] == pk.ID {
				if !Operation.GTEqual(cipherNIZK.CM.C1x[at], new(bn256.GT).Add(new(bn256.GT).Add(new(bn256.GT).ScalarMult(pp.GT, cipherNIZK.Lambda[at]), new(bn256.GT).ScalarMult(pk.AlphaGT, cipherNIZK.R[at])), new(bn256.GT).ScalarMult(cipher.CM.C1x[at], challenge))) {
					return false
				}
				if !Operation.G1Equal(cipherNIZK.CM.C2x[at], new(bn256.G1).Add(new(bn256.G1).Neg(new(bn256.G1).ScalarBaseMult(cipherNIZK.R[at])), new(bn256.G1).ScalarMult(cipher.CM.C2x[at], challenge))) {
					return false
				}
				if !Operation.G1Equal(cipherNIZK.CM.C3x[at], new(bn256.G1).Add(new(bn256.G1).ScalarMult(pk.BetaG1, cipherNIZK.R[at]), new(bn256.G1).Add(new(bn256.G1).ScalarBaseMult(cipherNIZK.Omega[at]), new(bn256.G1).ScalarMult(cipher.CM.C3x[at], challenge)))) {
					return false
				}
				F_delta := HashG1(pp, at)
				if !Operation.G1Equal(cipherNIZK.CM.C4x[at], new(bn256.G1).Add(new(bn256.G1).ScalarMult(F_delta, cipherNIZK.R[at]), new(bn256.G1).ScalarMult(cipher.CM.C4x[at], challenge))) {
					return false
				}
			}

		}
	}
	lambdaRecon, _ := LSSSRecon(cipher.Msp, cipherNIZK.Lambda)
	omegaRecon, _ := LSSSRecon(cipher.Msp, cipherNIZK.Omega)
	if !Operation.BigIntEqual(lambdaRecon, cipherNIZK.S) {
		return false
	}
	if !Operation.BigIntEqual(omegaRecon, big.NewInt(int64(0))) {
		return false
	}
	return true
}

func Decrypt(pp *PP, ct *Cipher, akSet []*AttrKey) (string, error) {
	// sanity checks
	if len(akSet) == 0 {
		return "", fmt.Errorf("empty set of attribute keys")
	}
	gid := akSet[0].Gid
	for _, k := range akSet {
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
	for _, k := range akSet {
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
		if ct.CM.C1x[at] != nil && ct.CM.C2x[at] != nil && ct.CM.C3x[at] != nil && ct.CM.C4x[at] != nil {
			num := new(bn256.GT).Add(ct.CM.C1x[at], bn256.Pair(ct.CM.C2x[at], aToK[at].EK1))
			num = new(bn256.GT).Add(num, bn256.Pair(ct.CM.C3x[at], hash))
			num = new(bn256.GT).Add(num, bn256.Pair(ct.CM.C4x[at], aToK[at].EK2))
			eggLambda[at] = num
		} else {
			fmt.Println(ct.CM.C1x[at] != nil, ct.CM.C2x[at] != nil, ct.CM.C3x[at] != nil, ct.CM.C4x[at] != nil)
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
	symKey := new(bn256.GT).Add(bn256.Pair(ct.CM.C0, pp.G2), new(bn256.GT).Neg(eggs))
	msg := SymEnc.XOREncryptDecrypt(ct.Ciphertext, SymEnc.KDF(symKey))
	fmt.Println(string(msg))
	return string(msg), nil
}
