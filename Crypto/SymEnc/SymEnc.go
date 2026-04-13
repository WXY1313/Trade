package SymEnc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"golang.org/x/crypto/pbkdf2"
)

func XOREncryptDecrypt(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

func KDF(gt *bn256.GT) []byte {
	hash := sha256.New()
	hash.Write([]byte(gt.String()))
	hashBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)
	password := hashBytes[0:16]
	salt := hashBytes[16:]
	fmt.Println(hashString, hex.EncodeToString(password), hex.EncodeToString(salt))
	key := pbkdf2.Key(password, salt, 10000, 512, sha256.New)
	return key
}
