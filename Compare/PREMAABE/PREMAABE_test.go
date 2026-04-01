package PREMAABE

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/WXY1313/Trade/Crypto/CPABE/Threshold/node"
	"github.com/WXY1313/Trade/Crypto/SymEnc"
	"github.com/fentec-project/bn256"
	"github.com/stretchr/testify/assert"
)

func TestPREMAABE(t *testing.T) {
	// create new MAABE struct with Global Parameters
	_, gt, _ := bn256.RandomGT(rand.Reader)
	SymEnc.KDF(gt)
	maabe := NewPREMAABE()
	pp := maabe.GlobalSetup()

	// create three authorities, each with two attributes
	attrSet1 := []string{"auth1:Attr1", "auth1:Attr2"}
	attrSet2 := []string{"auth2:Attr3", "auth2:Attr4"}
	attrSet3 := []string{"auth3:Attr5", "auth3:Attr6"}

	auth1, err := AuthSetup(pp, "auth1")
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth1", err)
	}
	auth2, err := AuthSetup(pp, "auth2")
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth2", err)
	}
	auth3, err := AuthSetup(pp, "auth3")
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth3", err)
	}

	// create a msp struct out of the threshold formula
	//Access Policy
	root := node.NewNode(false, 3, 3, big.NewInt(int64(0)), "")
	P_1 := node.NewNode(false, 3, 2, big.NewInt(int64(1)), "")
	P_D := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "auth1:Attr1")
	P_2 := node.NewNode(false, 2, 1, big.NewInt(int64(3)), "")
	root.Children = []*node.Node{P_1, P_D, P_2}
	P_A := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "auth1:Attr2")
	P_B := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "auth2:Attr3")
	P_C := node.NewNode(true, 0, 1, big.NewInt(int64(3)), "auth2:Attr4")
	P_1.Children = []*node.Node{P_A, P_B, P_C}
	P_E := node.NewNode(true, 0, 1, big.NewInt(int64(1)), "auth3:Attr5")
	P_F := node.NewNode(true, 0, 1, big.NewInt(int64(2)), "auth3:Attr6")
	P_2.Children = []*node.Node{P_E, P_F}

	//Authorized path
	path := node.NewNode(false, 3, 3, big.NewInt(int64(0)), "")
	P_1 = node.NewNode(false, 2, 2, big.NewInt(int64(1)), "")
	P_D = node.NewNode(true, 0, 1, big.NewInt(int64(2)), "auth1:Attr1")
	P_2 = node.NewNode(false, 1, 1, big.NewInt(int64(3)), "")
	path.Children = []*node.Node{P_1, P_D, P_2}
	P_A = node.NewNode(true, 0, 1, big.NewInt(int64(1)), "auth1:Attr2")
	P_B = node.NewNode(true, 0, 1, big.NewInt(int64(2)), "auth2:Attr3")
	P_1.Children = []*node.Node{P_A, P_B}
	P_E = node.NewNode(true, 0, 1, big.NewInt(int64(1)), "auth3:Attr5")
	P_2.Children = []*node.Node{P_E}

	// define the set of all public keys we use
	pkSet := []*AuthPK{auth1.PK, auth2.PK, auth3.PK}

	// choose a message
	msg := "Secret"

	// encrypt the message with the decryption policy in msp
	ct, err := Encrypt(pp, msg, root, pkSet)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v\n", err)
	}
	// choose a single user's Global ID
	gid := "gid1"
	key11, err := KeyGen(pp, gid, auth1, attrSet1[0])
	//keys1[1]
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	key12, err := KeyGen(pp, gid, auth1, attrSet1[1])
	//keys1[1]
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	// authority 2 issues keys to user
	key21, err := KeyGen(pp, gid, auth2, attrSet2[0])
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	// authority 3 issues keys to user
	key31, err := KeyGen(pp, gid, auth3, attrSet3[0])
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}

	ks := []*AttrKey{key11, key12, key21, key31} // ok

	secretX, rk, _ := ReKeyGen(gid, ks)
	reCipher, _ := ReEncrypt(pp, rk, ct)

	edk, _ := EDKGen(pp, secretX, root, pkSet)

	// try to decrypt all messages
	msg1, err := ReDecrypt(pp, ks, edk, reCipher, path)
	if err != nil {
		t.Fatalf("Error decrypting with keyset 1: %v\n", err)
	}
	assert.Equal(t, msg, msg1)

}
