package FSAC

import (
	"bytes"
	"fmt"
	"log"
	"math/big"
	"strconv"

	gss "github.com/WXY1313/Trade/Compare/FSAC/GSS"
	"github.com/WXY1313/Trade/Crypto/CPABE/lsss"
	"github.com/WXY1313/Trade/Crypto/CPABE/node"
	"github.com/WXY1313/Trade/Crypto/CPABE/opmatrix"
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
	//CT     []byte
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

func Encrypt(MPK *MPK, K *bn256.GT, policy *node.Node) (*FSACCiphertext, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	C1Set := make(map[string]*bn256.G1)
	C2Set := make(map[string]*bn256.G1)
	//Generate the ABE ciphertext

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
		//CT:     ct,
		Policy: policy, // (M, ρ)
		C:      c,      //C=e(hG1,uG2)^me(hG1,uG2)^{alpha*beta}
		_C:     _c,     //_C=gG2^{beta}
		C1:     C1Set,  //Ci  = h^{a*λi}hiG1^{-ri}
		C2:     C2Set,  //Ci' = hG1^{ri}
	}, nil

}

func CipherCheck(MPK *MPK, CT *FSACCiphertext, su []string, policy *node.Node, path *node.Node) (bool, error) {
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

	_, rowMap := node.Convert(policy)
	goodAttribs := make([]string, len(rowMap))
	for i := 0; i < len(rowMap); i++ {
		goodAttribs[i] = rowMap[i].Attribute
	}
	aToK := make(map[string]*bn256.G2)
	for at, k := range kxs {
		aToK[at] = k
	}
	ASet := make(map[string]*bn256.GT)
	for _, at := range goodAttribs {
		if CT.C1[at] != nil && CT.C2[at] != nil {
			num := bn256.Pair(CT.C1[at], l)
			num = num.Add(num, bn256.Pair(CT.C2[at], aToK[at]))
			ASet[at] = num
		} else {
			fmt.Println(CT.C1[at] != nil && CT.C2[at] != nil)
			return false, fmt.Errorf("attribute %s not in ciphertext dicts", at)
		}
	}
	A, err := gss.GssReconGT(policy, ASet)
	if err != nil {
		log.Fatalf("Fail to execute LSSSRecon ,Error: %v", err)
	}
	A = new(bn256.GT).Add(bn256.Pair(k, CT._C), new(bn256.GT).Neg(A))
	if !GTEqual(A, bn256.Pair(new(bn256.G1).ScalarBaseMult(y), CT._C)) {
		fmt.Printf("FSAC CT no Pass the check!!!\n")
		return false, err
	}
	return true, err
}

// FindReconstructionCoefficients 计算重构系数 vi
// 假设传入的 attributes 数量等于矩阵的列数 (即 M 是方阵)
func FindReconstructionCoefficients(AA *node.Node, attributes []string) (map[string]*big.Int, error) {
	// 1. 重新生成矩阵和属性映射 (必须与 Share 函数中使用的一致)
	matrix, rowMap := node.Convert(AA)
	if len(matrix) == 0 || len(matrix[0]) == 0 {
		return nil, fmt.Errorf("matrix is empty")
	}

	cols := len(matrix[0])
	//rows := len(matrix)

	// 2. 构建子矩阵 M_sub 和属性查找表
	// 我们需要找到 attributes 对应的行
	attrToRowIndex := make(map[string]int)
	for idx, rowInfo := range rowMap {
		attrToRowIndex[rowInfo.Attribute] = idx
	}

	// 提取子矩阵数据 (只提取 attributes 对应的行)
	var subMatrixData [][]*big.Int
	var selectedAttrs []string // 保持顺序

	for _, attr := range attributes {
		rowIdx, exists := attrToRowIndex[attr]
		if !exists {
			return nil, fmt.Errorf("attribute %s not found in matrix", attr)
		}
		// 深拷贝行数据
		rowCopy := make([]*big.Int, cols)
		for i, val := range matrix[rowIdx] {
			rowCopy[i] = new(big.Int).Set(val)
		}
		subMatrixData = append(subMatrixData, rowCopy)
		selectedAttrs = append(selectedAttrs, attr)
	}

	// 检查维度：为了使用逆矩阵，行数必须等于列数
	if len(subMatrixData) != cols {
		return nil, fmt.Errorf("number of attributes (%d) must equal matrix columns (%d) for inversion", len(subMatrixData), cols)
	}

	// 3. 构建目标向量 T = [1, 0, 0, ..., 0]
	targetVector := make([]*big.Int, cols)
	targetVector[0] = big.NewInt(1)
	for i := 1; i < cols; i++ {
		targetVector[i] = big.NewInt(0)
	}

	// 4. 求解系数 V = T * M_sub^(-1)
	// 步骤：
	// a. 计算 M_sub 的逆矩阵 (使用你提供的 GaussJordanInverse)
	// b. 计算 V = T * Inverse(M_sub)

	inverseMatrix, err := opmatrix.GaussJordanInverse(subMatrixData)
	if err != nil {
		return nil, fmt.Errorf("cannot invert sub-matrix: %v", err)
	}

	// 5. 计算 V = T * Inverse(M_sub)
	// 注意：T 是 1 x cols 的行向量。
	// 矩阵乘法：Result[1][cols] = T[1][cols] * Inverse[cols][cols]
	// 但是我们只需要计算结果行向量。

	resultCoeffs := make([]*big.Int, len(selectedAttrs))
	for i := 0; i < len(selectedAttrs); i++ {
		resultCoeffs[i] = big.NewInt(0)
	}

	// 手动计算行向量乘以矩阵
	// Result[j] = Sum_over_k ( T[k] * Inverse[k][j] )
	for j := 0; j < len(selectedAttrs); j++ {
		sum := big.NewInt(0)
		for k := 0; k < cols; k++ {
			// temp = T[k] * Inverse[k][j]
			temp := new(big.Int).Mul(targetVector[k], inverseMatrix[k][j])
			// temp = temp mod Order
			temp.Mod(temp, bn256.Order)
			sum.Add(sum, temp)
		}
		sum.Mod(sum, bn256.Order)
		resultCoeffs[j] = sum
	}

	// 6. 打包结果
	result := make(map[string]*big.Int)
	for i, attr := range selectedAttrs {
		result[attr] = resultCoeffs[i]
	}

	return result, nil
}

func Santize(MPK *MPK, Key *Key, CT *FSACCiphertext, ct []byte) ([]byte, *VKey, error) {
	sampler := sample.NewUniformRange(big.NewInt(1), MPK.Order)
	_k, _ := sampler.Sample()
	_K := new(bn256.GT).ScalarBaseMult(_k)
	sanCT := SymEnc.XOREncryptDecrypt(ct, SymEnc.KDF(_K))
	b, _ := sampler.Sample()
	v0 := new(bn256.GT).ScalarBaseMult(b)
	v1 := new(bn256.GT).Add(_K, new(bn256.GT).ScalarMult(Key.PK, b))
	return sanCT, &VKey{V0: v0, V1: v1}, nil
}

func Decrypt(MPK *MPK, CT *FSACCiphertext, SK *SK, VKey *VKey, Key *Key, ct []byte, policy *node.Node, path *node.Node) (*bn256.GT, *bn256.GT, error) {
	_, rowMap := node.Convert(path)
	goodAttribs := make([]string, len(rowMap))
	for i := 0; i < len(rowMap); i++ {
		goodAttribs[i] = rowMap[i].Attribute
	}
	aToK := make(map[string]*bn256.G2)
	for at, k := range SK.KXs {
		aToK[at] = k
	}
	ASet := make(map[string]*bn256.GT)
	for _, at := range goodAttribs {
		if CT.C1[at] != nil && CT.C2[at] != nil {
			num := bn256.Pair(CT.C1[at], SK.L)
			num = num.Add(num, bn256.Pair(CT.C2[at], aToK[at]))
			ASet[at] = num
		} else {
			fmt.Println(CT.C1[at] != nil && CT.C2[at] != nil)
			return nil, nil, fmt.Errorf("attribute %s not in ciphertext dicts", at)
		}
	}
	A, err := lsss.ReconGT(policy, ASet)
	if err != nil {
		log.Fatalf("Fail to execute LSSSRecon ,Error: %v", err)
	}
	A = new(bn256.GT).Add(bn256.Pair(SK.K, CT._C), new(bn256.GT).Neg(A))
	K := new(bn256.GT).Add(CT.C, new(bn256.GT).Neg(A))
	_K := new(bn256.GT).Add(VKey.V1, new(bn256.GT).Neg(new(bn256.GT).ScalarMult(VKey.V0, Key.SK)))

	return K, _K, nil
}
