package MAABEFE

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/WXY1313/Trade/Crypto/CPABE/node"
	"github.com/WXY1313/Trade/Crypto/SymEnc"

	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/sample"
	"github.com/stretchr/testify/assert"
)

func TestMAABEFE(t *testing.T) {
	n := float64(500)
	nx := 3
	tx := (nx + 1) / 2
	// create new MAABE struct with Global Parameters
	_, gt, _ := bn256.RandomGT(rand.Reader)
	SymEnc.KDF(gt)
	pp := GlobalSetup()

	// create three authorities, each with two attributes
	attrSet1 := []string{"auth1:Alice", "auth1:Bob"}
	attrSet2 := make([]string, nx)
	for i := 0; i < nx; i++ {
		attrSet2[i] = "auth2:p" + strconv.Itoa(i+1)
	}

	auth1, err := AuthSetup(pp, "auth1")
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth1", err)
	}
	auth2, err := AuthSetup(pp, "auth2")
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth2", err)
	}

	// create a msp struct out of the boolean formula
	//Access Policy
	root := node.NewNode(false, 3, 2, big.NewInt(int64(0)), "")
	P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "auth1:Alice")
	P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "auth1:Bob")
	P_1 := node.NewNode(false, nx, tx, big.NewInt(int64(3)), "")
	root.Children = []*node.Node{P_A, P_B, P_1}
	for i := 0; i < nx; i++ {
		P_1.Children = append(P_1.Children, node.NewNode(true, 0, 1, big.NewInt(int64(i+1)), "auth2:p"+strconv.Itoa(i+1)))
	}

	//Authorized path1
	path := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	path.Children = []*node.Node{P_A, P_B}
	// P_11 := node.NewNode(false, tx, tx, big.NewInt(int64(3)), "")
	// P_11.Children = P_1.Children[:tx]
	// path.Children = []*node.Node{P_A, P_11}

	// define the set of all public keys we use
	pkSet := []*AuthPK{auth1.PK, auth2.PK}

	// choose a message
	msg := "Secret"

	// encrypt the message with the decryption policy in msp
	sampler := sample.NewUniform(pp.P)
	m, _ := sampler.Sample()
	symKey := new(bn256.GT).ScalarBaseMult(m)
	ciphertext := SymEnc.XOREncryptDecrypt([]byte(msg), SymEnc.KDF(symKey))

	var ct *Cipher
	var nizk *NIZKCipher
	starttime := time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		ct, nizk, err = Encrypt(pp, m, root, pkSet)
	}
	endtime := time.Now().UnixMicro()
	fmt.Printf("Encrypt Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))
	if err != nil {
		t.Fatalf("Failed to encrypt: %v\n", err)
	}

	var cipherResult bool
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		cipherResult = CheckCipher(pp, ct, nizk, pkSet)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("EncVer Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))
	fmt.Printf("Ciphertext is %v\n", cipherResult)

	// choose a single user's Global ID
	gid := "gid1"
	// authority 1 issues keys to user
	key11, err := KeyGen(pp, gid, auth1, attrSet1[0])
	key12, err := KeyGen(pp, gid, auth1, attrSet1[1])
	ks := []*AttrKey{key11, key12} // ok
	// authority 2 issues keys to user
	for i := 0; i < tx; i++ {
		key, _ := KeyGen(pp, gid, auth2, attrSet2[i])
		ks = append(ks, key)
	}

	// try to decrypt all messages
	var recoverSymKey *bn256.GT
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		recoverSymKey, err = Decrypt(pp, ct, ks, path)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("Decrypt Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	if err != nil {
		t.Fatalf("Error decrypting with keyset 1: %v\n", err)
	}
	recoverMsg := SymEnc.XOREncryptDecrypt(ciphertext, SymEnc.KDF(recoverSymKey))
	assert.Equal(t, string(msg), string(recoverMsg))

}
