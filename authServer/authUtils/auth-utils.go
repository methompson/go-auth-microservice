package authUtils

import (
	"crypto"
	"fmt"
)

// Takes a string, converts to bytes and finds the sha3-512 hash from the
// bytes of that string.
func HashString(str string) string {
	strBytes := []byte(str)
	return HashBytes(strBytes)
}

// Takes an array of bytes and calculates the sha3-512 hash of the bytes array
func HashBytes(bytes []byte) string {
	// Hash the value using sha3-512
	hasher := crypto.SHA3_512.New()
	hasher.Write(bytes)
	sum := hasher.Sum(nil)
	sha3 := fmt.Sprintf("%x", sum)

	return sha3
}
