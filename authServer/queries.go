package authServer

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

const FIVE_MINUTES = 60 * 5

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
		return decodeStringErr
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

// Generate a random string of n bits length. 64 bits is a good starting point for
// generating a somewhat secure value. We return both a base 64 encoded string and
// the actual bytes. The string is, eventually returned to the client and the bytes
// are used for hashing the value and saving to the database. We could just return
// the base 64 encoded string and use a base 64 decoder, but returning the bytes
// representation should save a few ops
func GenerateRandomString(bits int) (string, []byte) {
	byt := make([]byte, bits)
	_, randReadErr := rand.Read(byt)

	if randReadErr != nil {
		errLog := fmt.Sprintln("Random Generator Error ", randReadErr)
		fmt.Println(errLog)
		log.Fatal(errLog)
	}

	b64 := base64.URLEncoding.EncodeToString(byt)

	return b64, byt
}

// Returns a JWT

func generateJWT(userDocument UserDocument) (string, error) {
	type CustomClaims struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		jwt.StandardClaims
	}

	claims := CustomClaims{
		userDocument.Username,
		userDocument.Email,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 4).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	privateKey, privateKeyErr := GetRSAPrivateKey()

	if privateKeyErr != nil {
		msg := fmt.Sprintln("error getting private key ", privateKeyErr)
		return "", errors.New(msg)
	}

	signedString, tokenStringErr := token.SignedString(privateKey)

	if tokenStringErr != nil {
		msg := fmt.Sprintln("error making JWT", tokenStringErr)
		return "", errors.New(msg)
	}

	return signedString, nil
}
