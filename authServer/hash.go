package authServer

import (
	"crypto"
	"encoding/base64"
	"fmt"
)

func hashString(str string) string {
	strBytes := []byte(str)
	return hashBytes(strBytes)
}

// Takes an array of bytes and calculates the sha3-512 hash of the bytes array
func hashBytes(bytes []byte) string {
	// Hash the value using sha3-512
	hasher := crypto.SHA3_512.New()
	hasher.Write(bytes)
	sum := hasher.Sum(nil)
	sha3 := fmt.Sprintf("%x", sum)

	return sha3
}

func GetHashedNonceFromBody(body LoginBody) (string, error) {
	bytes, decodeStringErr := base64.URLEncoding.DecodeString(body.Nonce)
	if decodeStringErr != nil {
		msg := fmt.Sprintln("Invalid Base64 value: ", decodeStringErr)
		return "", NewNonceError(msg)
	}

	hashedNonce := hashBytes(bytes)

	return hashedNonce, nil
}
