package authServer

import (
	"time"

	"github.com/gin-gonic/gin"

	"methompson.com/auth-microservice/authServer/authCrypto"
	"methompson.com/auth-microservice/authServer/authUtils"
	"methompson.com/auth-microservice/authServer/dbController"
)

// The purpose of the AuthController is to handle all logic associated with the
// server. This includes reviewing requests and determining which database functions
// to call, reviewing requests and determining which errors may be thrown.
type AuthController struct {
	DBController *dbController.DatabaseController
	Loggers      []*authUtils.AuthLogger
}

// The DatabaseController should already be initialized before getting
// passed to the InitController function
func InitController(dbc *dbController.DatabaseController) AuthController {
	ac := AuthController{
		DBController: dbc,
		Loggers:      make([]*authUtils.AuthLogger, 0),
	}

	return ac
}

func (ac *AuthController) LogUserIn(body LoginBody, ctx *gin.Context) (string, error) {
	// If we're not in debug mode OR we're in debug mode and we're NOT ignoring nonces
	if !DebugMode() || (!authUtils.IgnoringNonce() && DebugMode()) {
		nonceErr := ac.CheckNonceValidity(body.Nonce, ctx)

		if nonceErr != nil {
			return "", nonceErr
		}
	}

	userDoc, userDocErr := (*ac.DBController).GetUserByUsername(body.Username)
	if userDocErr != nil {
		return "", userDocErr
	}

	verify := authUtils.CheckPasswordHash(body.Password, userDoc.PasswordHash)
	if !verify {
		return "", NewLoginError("Password does not match")
	}

	return authCrypto.GenerateJWT(userDoc.GetUserDocument())
}

func (ac *AuthController) AddNewUser(body AddUserBody, ctx *gin.Context) error {
	// If we're not in debug mode OR we're in debug mode and we're NOT ignoring nonces
	if !DebugMode() || (!authUtils.IgnoringNonce() && DebugMode()) {
		nonceErr := ac.CheckNonceValidity(body.Nonce, ctx)

		if nonceErr != nil {
			return nonceErr
		}
	}

	hash, hashErr := authUtils.HashPassword(body.Password)
	if hashErr != nil {
		return NewHashError(hashErr.Error())
	}

	doc := dbController.FullUserDocument{
		Username:     body.Username,
		Email:        body.Email,
		Enabled:      body.Enabled,
		Admin:        body.Admin,
		PasswordHash: hash,
	}

	addErr := (*ac.DBController).AddUser(doc)

	return addErr
}

func (ac *AuthController) EditUser(body *EditUserBody, claims *authCrypto.JWTClaims, ctx *gin.Context) error {
	// If we're not in debug mode OR we're in debug mode and we're NOT ignoring nonces
	if !DebugMode() || (!authUtils.IgnoringNonce() && DebugMode()) {
		nonceErr := ac.CheckNonceValidity(body.Nonce, ctx)

		if nonceErr != nil {
			return nonceErr
		}
	}

	// If the user is not an admin, we need to check the user's id against the
	// token id. A non-admin can only edit their own data. If the token and
	// body ids don't match, we just return an error.
	if !claims.Admin && body.Id != claims.Subject {
		return NewUnauthorizedError("Not authorized to perform this action")
	}

	doc := dbController.EditUserDocument{
		Id:       body.Id,
		Username: body.Username,
		Email:    body.Email,
		Enabled:  body.Enabled,
		Admin:    body.Admin,
	}

	editErr := (*ac.DBController).EditUser(doc)

	return editErr
}

func (ac *AuthController) EditUserPassword(body *EditPasswordBody, claims *authCrypto.JWTClaims, ctx *gin.Context) error {
	// If we're not in debug mode OR we're in debug mode and we're NOT ignoring nonces
	if !DebugMode() || (!authUtils.IgnoringNonce() && DebugMode()) {
		nonceErr := ac.CheckNonceValidity(body.Nonce, ctx)

		if nonceErr != nil {
			return nonceErr
		}
	}

	// If the user is not an admin, we need to perform additional checks.
	if !claims.Admin {
		// We need to check the user's id against the token id. A non-admin can only edit
		// their own data. If the token and body ids don't match, we just return an error.
		if body.Id != claims.Subject {
			return NewUnauthorizedError("Not authorized to perform this action")
		}

		// Now, we need to fetch the user data, and compare the old password passed
		// to their current password.
		userDoc, userDocErr := (*ac.DBController).GetUserById(body.Id)
		if userDocErr != nil {
			return userDocErr
		}

		verify := authUtils.CheckPasswordHash(body.OldPassword, userDoc.PasswordHash)
		if !verify {
			return NewLoginError("Password does not match")
		}
	}

	// If we made it this far, we've passed all the checks. We can generated the password's
	// hash and save it.
	hashPass, hashErr := authUtils.HashPassword(body.NewPassword)
	if hashErr != nil {
		return NewHashError(hashErr.Error())
	}

	editPassErr := (*ac.DBController).EditUserPassword(body.Id, hashPass)

	return editPassErr
}

// This function receives a calculated hash of a nonce in string form. It performs
// a query of the list of hashed nonces in the database to determine if the combination
// of hashed nonce and remote address exists.
func (ac *AuthController) CheckNonceHash(hashedNonce string, ctx *gin.Context) error {
	// remoteAddress := authUtils.GetRemoteAddressIP(ctx.Request.RemoteAddr)
	remoteAddress := authUtils.GetRemoteAddressIP(ctx.ClientIP())

	_, nonceDocErr := (*ac.DBController).GetNonce(hashedNonce, remoteAddress, authUtils.GetNonceExpirationTime())

	if nonceDocErr != nil {
		return nonceDocErr
	}

	return nil
}

func (ac *AuthController) CheckNonceValidity(nonce string, ctx *gin.Context) error {
	// We get the hashed value of the byte array represented by the base64 encoded nonce.
	hashedNonce, hashedNonceErr := authUtils.GetHashedNonce(nonce)

	if hashedNonceErr != nil {
		return hashedNonceErr
	}

	// We Check if this nonce exists in the database.
	checkNonceErr := ac.CheckNonceHash(hashedNonce, ctx)

	if checkNonceErr != nil {
		return checkNonceErr
	}

	return nil
}

func (ac *AuthController) GenerateNonce(ctx *gin.Context) (string, error) {
	// remoteAddress := authUtils.GetRemoteAddressIP(ctx.Request.RemoteAddr)
	remoteAddress := authUtils.GetRemoteAddressIP(ctx.ClientIP())
	// clientIP := ctx.ClientIP()
	// fmt.Println("Remote Address (GenerateNonce): " + remoteAddress)
	// fmt.Println("Client IP (GenerateNonce): " + clientIP)

	// xfwd := ctx.Request.Header.Get("x-forwarded-for")
	// fmt.Println("X Forwarded For: " + xfwd)

	// Generate a random string and its source bytes
	nonce, bytes := GenerateRandomString(64)

	hash := authUtils.HashBytes(bytes)

	addNonceErr := (*ac.DBController).AddNonce(hash, remoteAddress, time.Now().Unix())

	if addNonceErr != nil {
		return "", addNonceErr
	}

	return nonce, nil
}

func (ac *AuthController) RemoveOldNonces() error {
	return (*ac.DBController).RemoveOldNonces(authUtils.GetNonceExpirationTime())
}

func (ac *AuthController) AddLogger(logger *authUtils.AuthLogger) {
	ac.Loggers = append(ac.Loggers, logger)
}

func (ac *AuthController) AddRequestLog(log *authUtils.RequestLogData) {
	for _, logger := range ac.Loggers {
		(*logger).AddRequestLog(log)
	}
}

func (ac *AuthController) AddInfoLog(log *authUtils.InfoLogData) {
	for _, logger := range ac.Loggers {
		(*logger).AddInfoLog(log)
	}
}

// We use this function to determine if a password is acceptable.
// The current test is to set a minimum password length. Later tests include
// checking for characters.
func (ac *AuthController) AcceptablePassword(pass string) bool {
	return len(pass) >= 10
}
