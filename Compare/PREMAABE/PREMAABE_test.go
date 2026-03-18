package PREMAABE

import (
	"crypto/rand"
	"testing"

	"github.com/WXY1313/Trade/Crypto/SymEnc"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/stretchr/testify/assert"
)

func TestPREMAABE(t *testing.T) {
	// create new MAABE struct with Global Parameters
	_, gt, _ := bn256.RandomGT(rand.Reader)
	SymEnc.KDF(gt)
	maabe := NewPREMAABE()
	pp := maabe.GlobalSetup()

	// create three authorities, each with two attributes
	attrSet1 := []string{"auth1:at1", "auth1:at2"}
	attrSet2 := []string{"auth2:at1", "auth2:at2"}
	attrSet3 := []string{"auth3:at1", "auth3:at2"}
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

	// create a msp struct out of the boolean formula
	msp, err := abe.BooleanToMSP("((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)", false)
	if err != nil {
		t.Fatalf("Failed to generate the policy: %v\n", err)
	}

	// define the set of all public keys we use
	pkSet := []*AuthPK{auth1.PK, auth2.PK, auth3.PK}

	// choose a message
	msg := "Secret"

	// encrypt the message with the decryption policy in msp
	ct, err := Encrypt(pp, msg, msp, pkSet)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v\n", err)
	}

	// choose a single user's Global ID
	gid := "gid1"
	// authority 1 issues keys to user
	key11, err := KeyGen(pp, gid, auth1, attrSet1[0])
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

	ks := []*AttrKey{key11, key21, key31} // ok

	secretX, rk, _ := ReKeyGen(gid, ks)
	reCipher, _ := ReEncrypt(pp, rk, ct)

	edk, _ := EDKGen(pp, secretX, msp, pkSet)

	// // try to decrypt all messages
	msg1, err := ReDecrypt(pp, ks, edk, reCipher)
	if err != nil {
		t.Fatalf("Error decrypting with keyset 1: %v\n", err)
	}
	assert.Equal(t, msg, msg1)

}
