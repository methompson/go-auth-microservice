package authServer

import (
	"github.com/gin-gonic/gin"
)

type AuthController struct {
	DBController *DatabaseController
}

// The DatabaseController should already be initialized before getting
// passed to the InitController function
func InitController(dbController *DatabaseController) AuthController {
	ac := AuthController{dbController}

	return ac
}

func (ac AuthController) LogUserIn(body LoginBody, ctx *gin.Context) (string, error) {
	hashedNonce, hashedNonceErr := GetHashedNonceFromBody(body)

	if hashedNonceErr != nil {
		return "", hashedNonceErr
	}

	checkNonceErr := ac.CheckNonceHash(hashedNonce, ctx)

	if checkNonceErr != nil {
		return "", checkNonceErr
	}

	userDoc, userDocErr := (*ac.DBController).GetUserByUsername(body.Username, body.Password)

	if userDocErr != nil {
		return "", userDocErr
	}

	return generateJWT(userDoc)
}

func (ac AuthController) CheckNonceHash(hashedNonce string, ctx *gin.Context) error {
	remoteAddress := ctx.Request.RemoteAddr
	_, nonceDocErr := (*ac.DBController).GetNonce(hashedNonce, remoteAddress)

	if nonceDocErr != nil {
		return nonceDocErr
	}

	return nil
}

func (ac AuthController) GenerateNonce(ctx *gin.Context) (string, error) {
	remoteAddress := ctx.Request.RemoteAddr

	// Generate a random string and its source bytes
	nonce, bytes := GenerateRandomString(64)

	hash := hashBytes(bytes)

	addNonceErr := (*ac.DBController).AddNonce(hash, remoteAddress)

	if addNonceErr != nil {
		return "", addNonceErr
	}

	return nonce, nil
}

func (ac AuthController) RemoveOldNonces() error {
	return (*ac.DBController).RemoveOldNonces()
}
