package sss

import (
	"crypto/rand"
	"fmt"

	"math/big"
	"testing"

	"github.com/fentec-project/bn256"
)

func TestSSS(t *testing.T) {
	n := 5         // The number of shares
	threshold := 3 // threshold

	// Generate a random secret
	s, _ := rand.Int(rand.Reader, bn256.Order)

	share, err := Share(s, n, threshold)
	if err != nil {
		t.Fatalf("Share failed: %v", err)
	}

	I := make([]*big.Int, threshold)
	for i := 0; i < threshold; i++ {
		I[i] = big.NewInt(int64(i + 1))
	}

	secret, err := Recon(share, I, threshold)
	if err != nil {
		t.Fatalf("Error in Recon: %v", err)
	}
	fmt.Println("recover secret = ", secret)
	fmt.Println("orignal secret = ", s)

	if s.Cmp(secret) != 0 {
		t.Fatal("Recovered secret does not match the original secret")
	}
}
