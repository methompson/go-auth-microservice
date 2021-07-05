package authServer

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// setRoutes sets all of the routes for the Gin Server
func (as AuthServer) setRoutes() {
	as.GinEngine.GET("/", as.getHomeRoute)
	as.GinEngine.GET("/nonce", as.getNonceRoute)
	as.GinEngine.GET("/public-key", as.getPublicKeyRoute)

	as.GinEngine.POST("/login", as.postLoginRoute)
	as.GinEngine.POST("/verify-token", as.postVerifyTokenRoute)
}

/****************************************************************************************
* Route Functions
****************************************************************************************/
func (as AuthServer) getHomeRoute(ctx *gin.Context) {
	ctx.Data(200, "text/html; charset=utf-8", make([]byte, 0))
}

// Returns a nonce value.
func (as AuthServer) getNonceRoute(ctx *gin.Context) {
	nonce, err := as.AuthDataController.GenerateNonce(ctx)

	if err != nil {
		ctx.JSON(500, gin.H{})
		return
	}

	ctx.JSON(200, gin.H{
		"nonce": nonce,
	})
}

// Takes a user's nonce, username and password and confirms the data on behalf of
// the user. Returns a JWT that a user can use for authorization purposes.
func (as AuthServer) postLoginRoute(ctx *gin.Context) {
	var body LoginBody

	if bindJsonErr := ctx.ShouldBindJSON(&body); bindJsonErr != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": bindJsonErr.Error()})
		return
	}

	token, loginError := as.AuthDataController.LogUserIn(body, ctx)

	if loginError != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": loginError.Error()})
		return
	}

	ctx.JSON(200, gin.H{
		"token": token,
	})
}

// Verifies JWT tokens.
// TODO implement postVerifyTokenRoute
func (as AuthServer) postVerifyTokenRoute(ctx *gin.Context) {
	ctx.JSON(200, gin.H{
		"verify": "verify",
	})
}

// Prints the RSA Public Key for JWT verification
func (as AuthServer) getPublicKeyRoute(ctx *gin.Context) {
	ctx.String(200, os.Getenv(RSA_PUBLIC_KEY))
}
