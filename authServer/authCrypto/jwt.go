package authCrypto

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"

	"methompson.com/auth-microservice/authServer/constants"
	dbc "methompson.com/auth-microservice/authServer/dbController"
)

/****************************************************************************************
* JWT Errors
****************************************************************************************/

// Used for when there's a generic issue reading or writing JWTs
type JWTError struct{ ErrMsg string }

func (err JWTError) Error() string { return err.ErrMsg }
func NewJWTError(msg string) error { return JWTError{msg} }

// Used for when the JWT expires
type ExpiredJWTError struct{ ErrMsg string }

func (err ExpiredJWTError) Error() string { return err.ErrMsg }
func NewExpiredJWTError(msg string) error { return ExpiredJWTError{msg} }

/****************************************************************************************
* JWT Claims Struct
****************************************************************************************/

type JWTClaims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Admin    bool   `json:"admin"`
	jwt.StandardClaims
}

func (jc JWTClaims) Valid() error {
	return nil
}

/****************************************************************************************
* Generating and Validating JWTs
****************************************************************************************/

func GetJWTExpirationTime() int64 {
	return time.Now().Add(constants.JWT_EXPIRATION).Unix()
}

// Returns a JWT
func GenerateJWT(userDocument dbc.UserDocument) (string, error) {
	claims := JWTClaims{
		Username: userDocument.Username,
		Email:    userDocument.Email,
		Admin:    userDocument.Admin,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: GetJWTExpirationTime(),
			Subject:   userDocument.Id,
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

func ValidateJWT(tokenString string) (*JWTClaims, error) {
	var jwtClaims *JWTClaims = &JWTClaims{}
	// token, parseErr := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	token, parseErr := jwt.ParseWithClaims(tokenString, jwtClaims, func(token *jwt.Token) (interface{}, error) {
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

	if !token.Valid {
		return nil, NewJWTError("invalid claims")
	}

	return jwtClaims, nil
}
