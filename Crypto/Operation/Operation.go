package Operation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"time"

	"Trade/compile/contract"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
)

func RandomString(sizeKB float64) string {
	// 定义允许的字符集：大写字母、小写字母、数字
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 计算字符串需要的字节数
	numBytes := int(sizeKB * 1024) // size in bytes (1 KB = 1024 bytes)

	// 使用当前时间作为随机数种子
	rand.Seed(time.Now().UnixNano())

	// 创建一个字符切片
	var randomString []byte
	for i := 0; i < numBytes; i++ {
		randomByte := charset[rand.Intn(len(charset))]
		randomString = append(randomString, randomByte)
	}

	// 返回生成的字符串
	return string(randomString)
}

func MapToVector(m map[string]*big.Int) data.Vector {

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	vec := make(data.Vector, len(keys))

	for i, k := range keys {
		vec[i] = m[k]
	}

	return vec
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

func BigIntEqual(a, b *big.Int) bool {
	return a.Cmp(b) == 0 // 如果 a 和 b 相等，返回 true
}

func RandomInt() *big.Int {
	v, _ := data.NewRandomVector(1, sample.NewUniform(bn256.Order))
	return v[0]
}

func G1ToG1Point(bn256Point *bn256.G1) contract.TradeG1Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	point := bn256Point.Marshal()

	// Create big.Int for X and Y coordinates
	x := new(big.Int).SetBytes(point[:32])
	y := new(big.Int).SetBytes(point[32:64])

	g1Point := contract.TradeG1Point{
		X: x,
		Y: y,
	}
	return g1Point
}

func G1PointToG1(g1point contract.TradeG1Point) (*bn256.G1, error) {
	// 将 x 和 y 转换为字节数组
	xBytes := g1point.X.Bytes()
	yBytes := g1point.Y.Bytes()

	// 检查字节数组的长度是否为32
	if len(xBytes) != 32 {
		xBytes = append([]byte{0x00}, xBytes...)
		fmt.Errorf("xBytes length is not 32, got %d", len(xBytes))
		//return nil, fmt.Errorf("xBytes length is not 32, got %d", len(xBytes))
	}
	if len(yBytes) != 32 {
		yBytes = append([]byte{0x00}, yBytes...)
		fmt.Errorf("yBytes length is not 32, got %d", len(yBytes))
		//return nil, fmt.Errorf("yBytes length is not 32, got %d", len(yBytes))
	}

	// 将两个字节数组拼接起来
	decodedBytes := append(xBytes, yBytes...)

	g1 := new(bn256.G1)
	_, err := g1.Unmarshal(decodedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal G1: %v", err)
	}
	return g1, nil
	//return new(bn256.G1).Unmarshal(decodedBytes)
}

func G2ToG2Point(point *bn256.G2) contract.TradeG2Point {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()

	// Create big.Int for X and Y coordinates
	a1 := new(big.Int).SetBytes(pointBytes[:32])
	a2 := new(big.Int).SetBytes(pointBytes[32:64])
	b1 := new(big.Int).SetBytes(pointBytes[64:96])
	b2 := new(big.Int).SetBytes(pointBytes[96:128])

	g2Point := contract.TradeG2Point{
		X: [2]*big.Int{a1, a2},
		Y: [2]*big.Int{b1, b2},
	}
	return g2Point
}

// func G2ToG2Point(point *bn256.G2) contract.TradeG2Point {
// 	// Marshal the G1 point to get the X and Y coordinates as bytes
// 	pointBytes := point.Marshal()
// 	//fmt.Println(point.Marshal())

// 	// Create big.Int for X and Y coordinates
// 	a1 := new(big.Int).SetBytes(pointBytes[:32])
// 	a2 := new(big.Int).SetBytes(pointBytes[32:64])
// 	b1 := new(big.Int).SetBytes(pointBytes[64:96])
// 	b2 := new(big.Int).SetBytes(pointBytes[96:128])

// 	g2Point := contract.TradeG2Point{
// 		X: [2]*big.Int{a1, a2},
// 		Y: [2]*big.Int{b1, b2},
// 	}
// 	return g2Point
// }

func G2PointToG2(g2point contract.TradeG2Point) (*bn256.G2, error) {
	// 将 X 和 Y 中的每个元素转换为字节数组
	x1Bytes := g2point.X[0].Bytes()
	x2Bytes := g2point.X[1].Bytes()
	y1Bytes := g2point.Y[0].Bytes()
	y2Bytes := g2point.Y[1].Bytes()
	// 检查字节数组的长度是否为32
	if len(x1Bytes) != 32 {
		x1Bytes = append([]byte{0x00}, x1Bytes...)
		fmt.Errorf("xBytes length is not 32, got %d", len(x1Bytes))
		//return nil, fmt.Errorf("xBytes length is not 32, got %d", len(xBytes))
	}
	if len(x1Bytes) != 32 {
		x2Bytes = append([]byte{0x00}, x2Bytes...)
		fmt.Errorf("xBytes length is not 32, got %d", len(x2Bytes))
		//return nil, fmt.Errorf("xBytes length is not 32, got %d", len(xBytes))
	}
	if len(y1Bytes) != 32 {
		y1Bytes = append([]byte{0x00}, y1Bytes...)
		fmt.Errorf("yBytes length is not 32, got %d", len(y1Bytes))
		//return nil, fmt.Errorf("yBytes length is not 32, got %d", len(yBytes))
	}
	if len(y2Bytes) != 32 {
		y2Bytes = append([]byte{0x00}, y2Bytes...)
		fmt.Errorf("yBytes length is not 32, got %d", len(y2Bytes))
		//return nil, fmt.Errorf("yBytes length is not 32, got %d", len(yBytes))
	}

	// 将四个字节数组拼接成一个完整的字节数组
	decodedBytes := append(x1Bytes, x2Bytes...)
	decodedBytes = append(decodedBytes, y1Bytes...)
	decodedBytes = append(decodedBytes, y2Bytes...)

	g2 := new(bn256.G2)
	_, err := g2.Unmarshal(decodedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal G2: %v", err)
	}
	return g2, nil
}

// GTToString 将 bn256.GT 元素编码为 Base64 字符串
func GTToString(gt *bn256.GT) string {

	// 使用 Marshal 将 GT 序列化为字节切片
	gtBytes := gt.Marshal()

	// 使用 Base64 编码为字符串
	encoded := base64.StdEncoding.EncodeToString(gtBytes)
	return encoded
}

func StringToGT(encoded string) (*bn256.GT, error) {
	// 使用 Base64 解码为字节切片
	decodedBytes, _ := base64.StdEncoding.DecodeString(encoded)
	// 使用 Unmarshal 还原为 GT 元素
	gt := new(bn256.GT)
	_, err := gt.Unmarshal(decodedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal GT: %v", err)
	}
	return gt, nil
}

func StringToBigInt(input string) *big.Int {
	// 使用 SHA-256 计算字符串的哈希值
	hash := sha256.Sum256([]byte(input))

	// 将哈希值转换为 big.Int
	bigIntValue := new(big.Int).SetBytes(hash[:])

	return bigIntValue
}

func G1ToBigIntArray(point *bn256.G1) [2]*big.Int {
	// Marshal the G1 point to get the X and Y coordinates as bytes
	pointBytes := point.Marshal()

	// Create big.Int for X and Y coordinates
	x := new(big.Int).SetBytes(pointBytes[:32])
	y := new(big.Int).SetBytes(pointBytes[32:64])

	return [2]*big.Int{x, y}
}
