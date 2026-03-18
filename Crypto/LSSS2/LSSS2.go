// Implementation of PVGSS based on GSS from LSSS.
package pvgss_lsss

import (
	"fmt"
	"math/big"

	"github.com/fentec-project/bn256"
	lib "github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

type GSS struct {
	P *big.Int
}
type GSSShare struct {
	// represent shareholder
	ID string
	// share value
	value *big.Int
}

type PvGSS struct {
	P  *big.Int
	G1 *bn256.G1
	G2 *bn256.G2
	Gt *bn256.GT
}

// NewGSS configures a new instance of the scheme.
func NewGSS(order *big.Int) *GSS {
	return &GSS{
		P: order,
	}
}

func NewPvGSS() *PvGSS {
	gen1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	gen2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	return &PvGSS{
		P:  bn256.Order,
		G1: gen1,
		G2: gen2,
		Gt: bn256.Pair(gen1, gen2),
	}
}

func (a *GSS) LSSShare(s *big.Int, msp *lib.MSP) ([]*GSSShare, error) {
	// sanity checks
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}
	mspRows := msp.Mat.Rows()
	mspCols := msp.Mat.Cols()
	holders := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if holders[i] {
			return nil, fmt.Errorf("some holders correspond to" +
				"multiple rows of the MSP struct, the scheme is not secure")
		}
		holders[i] = true
	}

	//using LSSS share

	// rand generator
	sampler := sample.NewUniform(a.P)
	// pick random vector v
	v, err := data.NewRandomVector(mspCols, sampler)
	if err != nil {
		return nil, err
	}
	// set first element as secret s
	v[0] = s

	//get shares which belongs to shareholders \rho(i)
	lambdaI, err := msp.Mat.MulVec(v)
	if err != nil {
		return nil, err
	}
	if len(lambdaI) != mspRows {
		return nil, fmt.Errorf("wrong lambda len")
	}

	shares := make([]*GSSShare, len(lambdaI))

	// Iterate through lambdaI and msp.RowToAttrib to create GSSShare
	for i := 0; i < len(lambdaI); i++ {
		shares[i] = &GSSShare{
			ID:    msp.RowToAttrib[i], // Set the attribute name as ID
			value: lambdaI[i],         // Set the corresponding share
		}
	}
	return shares, nil
}

func (a *GSS) LSSSRecon(msp *lib.MSP, shares []*GSSShare) (*big.Int, error) {
	goodMatRows := make([]data.Vector, 0)
	goodHolders := make([]string, 0)
	idToShare := make(map[string]*big.Int)
	for _, share := range shares {
		idToShare[share.ID] = share.value
	}
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
	c, err := data.GaussianEliminationSolver(goodMat.Transpose(), one, a.P)
	if err != nil {
		return nil, err
	}
	//for debug
	//for i, ci := range c {
	//	fmt.Println("gssrecon c", i, "=", ci)
	//}
	s := big.NewInt(0)
	for i, id := range goodHolders {
		s.Add(s, new(big.Int).Mul(c[i], idToShare[id]))
	}
	s.Mod(s, a.P)
	return s, nil
}
