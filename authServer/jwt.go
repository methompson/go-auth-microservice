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
		Admin    bool   `json:"admin"`
		jwt.StandardClaims
	}

	claims := CustomClaims{
		userDocument.Username,
		userDocument.Email,
		userDocument.Admin,
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

func validateJWT(tokenString string) (*jwt.MapClaims, error) {
	token, parseErr := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			// return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			return nil, NewJWTError(fmt.Sprintf("invalid signing method: %v", token.Header["alg"]))
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return GetRSAPublicKey()
	})

	if parseErr != nil {
		return nil, parseErr
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		return nil, NewJWTError("invalid claims")
	}

	return &claims, nil
}
