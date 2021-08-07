package authServer

import (
	"encoding/base64"
	"fmt"

	au "methompson.com/auth-microservice/authServer/authUtils"
)

func GetHashedNonceFromBody(body LoginBody) (string, error) {
	bytes, decodeStringErr := base64.URLEncoding.DecodeString(body.Nonce)
	if decodeStringErr != nil {
		msg := fmt.Sprintln("Invalid Base64 value: ", decodeStringErr)
		return "", NewNonceError(msg)
	}

	hashedNonce := au.HashBytes(bytes)

	return hashedNonce, nil
}
