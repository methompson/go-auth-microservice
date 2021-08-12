package authServer

import (
	"encoding/base64"
	"fmt"

	au "methompson.com/auth-microservice/authServer/authUtils"
)

func GetHashedNonce(nonce string) (string, error) {
	bytes, decodeStringErr := base64.URLEncoding.DecodeString(nonce)
	if decodeStringErr != nil {
		msg := fmt.Sprintln("Invalid Base64 value: ", decodeStringErr)
		return "", NewNonceError(msg)
	}

	hashedNonce := au.HashBytes(bytes)

	return hashedNonce, nil
}
