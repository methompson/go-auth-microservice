package authServer

import (
	"fmt"

	"github.com/golang-jwt/jwt"

	dbc "methompson.com/auth-microservice/authServer/dbController"
)

// Returns a JWT
func generateJWT(userDocument dbc.UserDocument) (string, error) {
	type CustomClaims struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		jwt.StandardClaims
	}

	claims := CustomClaims{
		userDocument.Username,
		userDocument.Email,
		jwt.StandardClaims{
			ExpiresAt: GetJWTExpirationTime(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	privateKey, privateKeyErr := GetRSAPrivateKey()

	if privateKeyErr != nil {
		// msg := fmt.Sprintln("error getting private key ", privateKeyErr)
		return "", privateKeyErr
	}

	signedString, tokenStringErr := token.SignedString(privateKey)

	if tokenStringErr != nil {
		msg := fmt.Sprintln("error making JWT", tokenStringErr)
		return "", NewJWTError(msg)
	}

	return signedString, nil
}
