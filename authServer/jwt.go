package authServer

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

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
		return "", NewJWTError(msg)
	}

	signedString, tokenStringErr := token.SignedString(privateKey)

	if tokenStringErr != nil {
		msg := fmt.Sprintln("error making JWT", tokenStringErr)
		return "", NewJWTError(msg)
	}

	return signedString, nil
}