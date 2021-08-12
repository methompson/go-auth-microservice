package authServer

import (
	"time"

	"github.com/gin-gonic/gin"

	au "methompson.com/auth-microservice/authServer/authUtils"
	dbc "methompson.com/auth-microservice/authServer/dbController"
)

type AuthController struct {
	DBController *dbc.DatabaseController
	Loggers      []*au.AuthLogger
}

// The DatabaseController should already be initialized before getting
// passed to the InitController function
func InitController(dbController *dbc.DatabaseController) AuthController {
	ac := AuthController{
		DBController: dbController,
		Loggers:      make([]*au.AuthLogger, 0),
	}

	return ac
}

func (ac *AuthController) LogUserIn(body LoginBody, ctx *gin.Context) (string, error) {
	nonceErr := ac.CheckNonceValidity(body.Nonce, ctx)

	if nonceErr != nil {
		return "", nonceErr
	}

	userDoc, userDocErr := (*ac.DBController).GetUserByUsername(body.Username, au.HashString(body.Password))

	if userDocErr != nil {
		return "", userDocErr
	}

	return generateJWT(userDoc)
}

func (ac *AuthController) AddNewUser(body AddUserBody, ctx *gin.Context) error {
	nonceErr := ac.CheckNonceValidity(body.Nonce, ctx)

	if nonceErr != nil {
		return nonceErr
	}

	doc := dbc.UserDocument{
		Username: body.Username,
		Email:    body.Email,
		Enabled:  body.Enabled,
		Admin:    body.Admin,
	}

	addErr := (*ac.DBController).AddUser(doc, au.HashString(body.Password))

	return addErr
}

func (ac *AuthController) EditUser(body LoginBody) error {
	return nil
}

func (ac *AuthController) CheckNonceHash(hashedNonce string, ctx *gin.Context) error {
	remoteAddress := ctx.Request.RemoteAddr
	_, nonceDocErr := (*ac.DBController).GetNonce(hashedNonce, remoteAddress, GetNonceExpirationTime())

	if nonceDocErr != nil {
		print("nonceDocErr " + nonceDocErr.Error() + "\n")
		return nonceDocErr
	}

	return nil
}

func (ac *AuthController) CheckNonceValidity(nonce string, ctx *gin.Context) error {
	hashedNonce, hashedNonceErr := GetHashedNonce(nonce)

	if hashedNonceErr != nil {
		print("hashedNonceErr " + hashedNonceErr.Error() + "\n")
		return hashedNonceErr
	}

	checkNonceErr := ac.CheckNonceHash(hashedNonce, ctx)

	if checkNonceErr != nil {
		print("checkNonceErr " + checkNonceErr.Error() + "\n")
		return checkNonceErr
	}

	return nil
}

func (ac *AuthController) GenerateNonce(ctx *gin.Context) (string, error) {
	remoteAddress := ctx.Request.RemoteAddr

	// Generate a random string and its source bytes
	nonce, bytes := GenerateRandomString(64)

	hash := au.HashBytes(bytes)

	addNonceErr := (*ac.DBController).AddNonce(hash, remoteAddress, time.Now().Unix())

	if addNonceErr != nil {
		return "", addNonceErr
	}

	return nonce, nil
}

func (ac *AuthController) RemoveOldNonces() error {
	return (*ac.DBController).RemoveOldNonces(GetNonceExpirationTime())
}

func (ac *AuthController) AddLogger(logger *au.AuthLogger) {
	ac.Loggers = append(ac.Loggers, logger)
}

func (ac *AuthController) AddRequestLog(log *au.RequestLogData) {
	for _, logger := range ac.Loggers {
		(*logger).AddRequestLog(log)
	}
}

func (ac *AuthController) AddInfoLog(log *au.InfoLogData) {
	for _, logger := range ac.Loggers {
		(*logger).AddInfoLog(log)
	}
}
