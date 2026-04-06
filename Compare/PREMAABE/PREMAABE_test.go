package PREMAABE

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/WXY1313/Trade/crypto/CPABE/node"
	"github.com/WXY1313/Trade/crypto/SymEnc"
	"github.com/fentec-project/bn256"
	"github.com/stretchr/testify/assert"
)

func TestPREMAABE(t *testing.T) {
	n := float64(500)
	// create new MAABE struct with Global Parameters
	_, gt, _ := bn256.RandomGT(rand.Reader)
	SymEnc.KDF(gt)
	maabe := NewPREMAABE()
	pp := maabe.GlobalSetup()

	//Original Access Policy
	onx := 14
	otx := 1
	origRoot := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	OP_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "auth0:AttrA")
	OP_1 := node.NewNode(false, onx, otx, big.NewInt(int64(2)), "")
	for i := 0; i < onx; i++ {
		ch := byte(66 + i)
		OP_1.Children = append(OP_1.Children, node.NewNode(true, 0, 1, big.NewInt(int64(i+1)), "auth0:Attr"+string(ch)))
	}
	origRoot.Children = []*node.Node{OP_A, OP_1}

	//Original authorilized path
	origPath := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	OPath_1 := node.NewNode(false, otx, otx, big.NewInt(int64(2)), "")
	OPath_1.Children = OP_1.Children[:otx]
	origPath.Children = []*node.Node{OP_A, OPath_1}

	//Init Authority
	auth0, err := AuthSetup(pp, "auth0")
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth0", err)
	}
	orgiPkSet := []*AuthPK{auth0.PK}

	//Generate Seller's AK
	attrSet0 := []string{}
	for i := 0; i < onx+1; i++ {
		ch := byte(65 + i)
		attrSet0 = append(attrSet0, "auth0:Attr"+string(ch))
	}
	gid0 := "gid0"
	ks0 := []*AttrKey{} // ok
	for i := 0; i < len(attrSet0); i++ {
		key, err := KeyGen(pp, gid0, auth0, attrSet0[i])
		if err != nil {
			t.Fatalf("Failed to generate attribute keys: %v\n", err)
		}
		ks0 = append(ks0, key)
	}

	// choose a message
	msg := "Secret"
	// msg is encrypted with AES-CBC with a random key that is encrypted with
	// MA-ABE
	// generate secret key
	_, symKey, err := bn256.RandomGT(rand.Reader)
	//fmt.Println(symKey)
	ciphertext := SymEnc.XOREncryptDecrypt([]byte(msg), SymEnc.KDF(symKey))

	//Create the original ciphertext
	ct, err := Encrypt(pp, symKey, origRoot, orgiPkSet)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v\n", err)
	}

	//Init Authority
	attrSet := []string{"auth1:Attr1", "auth1:Attr2", "auth1:Attr3", "auth1:Attr4", "auth1:Attr5", "auth1:Attr6", "auth1:Attr7", "auth1:Attr8", "auth1:Attr9", "auth1:Attr10", "auth1:Attr11", "auth1:Attr12", "auth1:Attr13", "auth1:Attr14", "auth1:Attr15", "auth1:Attr16", "auth1:Attr17"}
	auth1, err := AuthSetup(pp, "auth1")
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth1", err)
	}
	// define the set of all public keys we use
	pkSet := []*AuthPK{auth1.PK}

	//New Access Control
	nx := 15
	tx := 5
	root := node.NewNode(false, 3, 2, big.NewInt(int64(0)), "")
	P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "auth1:Attr1")
	P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "auth1:Attr2")
	P_1 := node.NewNode(false, nx, tx, big.NewInt(int64(3)), "")
	root.Children = []*node.Node{P_A, P_B, P_1}
	for i := 0; i < nx; i++ {
		P_1.Children = append(P_1.Children, node.NewNode(true, 0, 1, big.NewInt(int64(i+1)), "auth1:Attr"+strconv.Itoa(i+3)))
	}

	//Authorized path
	path := node.NewNode(false, 2, 2, big.NewInt(int64(0)), "")
	Path_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "auth1:Attr1")
	Path_1 := node.NewNode(false, tx, tx, big.NewInt(int64(3)), "")
	Path_1.Children = P_1.Children[:tx]
	path.Children = []*node.Node{Path_A, Path_1}

	// choose a single user's Global ID
	gid := "gid1"
	ks := []*AttrKey{} // ok
	for i := 0; i < len(attrSet); i++ {
		key, err := KeyGen(pp, gid, auth1, attrSet[i])
		if err != nil {
			t.Fatalf("Failed to generate attribute keys: %v\n", err)
		}
		ks = append(ks, key)
	}

	// Seller generates the subscription ciphertext

	//Generate and Check Ciphertext
	var secretX *bn256.GT
	var rk *ReKey
	starttime := time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		secretX, rk, _ = ReKeyGen(gid0, ks0)
	}
	endtime := time.Now().UnixMicro()
	fmt.Printf("ReKey(=Subscribe) Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	var edk *EDK
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		edk, _ = EDKGen(pp, secretX, root, pkSet)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("EDKGen(=Encrypt) Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	reCipher, _ := ReEncrypt(pp, rk, ct, origPath)

	// try to decrypt all messages
	var recoverKey *bn256.GT
	starttime = time.Now().UnixMicro()
	for k := 0; k < int(n); k++ {
		recoverKey, err = ReDecrypt(pp, ks, edk, reCipher, path)
	}
	endtime = time.Now().UnixMicro()
	fmt.Printf("ReDecrypt(=Decrypt) Algorithm Time Used is %.2f ms\n", (float64(endtime-starttime)/n)/float64(1000))

	recoverMsg := SymEnc.XOREncryptDecrypt(ciphertext, SymEnc.KDF(recoverKey))
	if err != nil {
		t.Fatalf("Error decrypting with keyset 1: %v\n", err)
	}
	fmt.Printf("recoverMsg=%v\n", string(recoverMsg))
	assert.Equal(t, string(msg), string(recoverMsg))

}
