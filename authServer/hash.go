package authServer

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/gin-gonic/gin"
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

// This function will accept the login body data, the request context and the mongodb
// client. It calculates the hash from the base 64 encoded data, then looks for the
// hash in the authNonces Document collection.
func CheckNonceHash(body LoginBody, ctx *gin.Context, dataController AuthController) error {
	bytes, decodeStringErr := base64.URLEncoding.DecodeString(body.Nonce)
	if decodeStringErr != nil {
		msg := fmt.Sprintln("Invalid Base64 value: ", decodeStringErr)
		fmt.Println(msg)
		return NewNonceError(msg)
	}

	hashedNonce := hashBytes(bytes)

	remoteAddress := ctx.Request.RemoteAddr

	_, nonceDocErr := dataController.GetNonceFromDb(hashedNonce, remoteAddress)

	if nonceDocErr != nil {
		return nonceDocErr
	}

	// TODO immediately write that the nonce has been used.
	err := dataController.RemoveUsedNonce(hashedNonce)

	if err != nil {
		fmt.Println("Error Deleting Nonce: ", err)
	}

	return nil
}
