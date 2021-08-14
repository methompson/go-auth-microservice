package authServer

import (
	"encoding/base64"
	"fmt"
	"os"

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

func IgnoringNonce() bool {
	return os.Getenv(IGNORE_NONCE) == "true" && os.Getenv(GIN_MODE) != "release"
}
