package authUtils

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"methompson.com/auth-microservice/authServer/constants"
)

const IGNORE_NONCE = "IGNORE_NONCE"

// Used for when there's an issue with reading Nonces
type NonceError struct{ ErrMsg string }

func (err NonceError) Error() string { return err.ErrMsg }
func NewNonceError(msg string) error { return NonceError{msg} }

// This function takes the base64 string [nonce], decodes it into
// a byte array, then calculates the sha3-512 hash string and returns
// that value. It returns an empty string and NonceError if the nonce
// string passed to the functions is not valid
func GetHashedNonce(nonce string) (string, error) {
	bytes, decodeStringErr := base64.URLEncoding.DecodeString(nonce)
	if decodeStringErr != nil {
		msg := fmt.Sprintln("Invalid Base64 value: ", decodeStringErr)
		return "", NewNonceError(msg)
	}

	hashedNonce := HashBytes(bytes)

	return hashedNonce, nil
}

func IgnoringNonce() bool {
	return os.Getenv(IGNORE_NONCE) == "true"
}

func GetNonceExpirationTime() int64 {
	return time.Now().Add(constants.NONCE_EXPIRATION).Unix()
}
