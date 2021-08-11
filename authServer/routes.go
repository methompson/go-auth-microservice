package authServer

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	dbc "methompson.com/auth-microservice/authServer/dbController"
)

// setRoutes sets all of the routes for the Gin Server
func (as *AuthServer) setRoutes() {
	as.GinEngine.GET("/", as.getHomeRoute)
	as.GinEngine.GET("/nonce", as.getNonceRoute)
	as.GinEngine.GET("/public-key", as.getPublicKeyRoute)

	as.GinEngine.POST("/login", as.postLoginRoute)
	as.GinEngine.POST("/add-user", as.addUser)
	as.GinEngine.POST("/edit-user", as.editUser)
}

/****************************************************************************************
* Route Functions
****************************************************************************************/
func (as *AuthServer) getHomeRoute(ctx *gin.Context) {
	ctx.Data(200, "text/html; charset=utf-8", make([]byte, 0))
}

// Returns a nonce value.
func (as *AuthServer) getNonceRoute(ctx *gin.Context) {
	nonce, err := as.AuthController.GenerateNonce(ctx)

	if err != nil {
		msg := "Unknown Error"
		errCode := http.StatusInternalServerError

		switch err.(type) {
		case dbc.DBError:
			msg = "Server Error"
			errCode = http.StatusInternalServerError
		}

		ctx.JSON(errCode, gin.H{
			"error": msg,
		})
		return
	}

	ctx.JSON(200, gin.H{
		"nonce": nonce,
	})
}

// Takes a user's nonce, username and password and confirms the data on behalf of
// the user. Returns a JWT that a user can use for authorization purposes.
// /login
func (as *AuthServer) postLoginRoute(ctx *gin.Context) {
	var body LoginBody

	if bindJsonErr := ctx.ShouldBindJSON(&body); bindJsonErr != nil {
		ctx.JSON(
			http.StatusBadRequest,
			gin.H{"error": "Invalid Body"},
			// gin.H{"error": bindJsonErr.Error()},
		)
		return
	}

	token, loginError := as.AuthController.LogUserIn(body, ctx)

	if loginError != nil {
		msg := "Unknown Error"
		errCode := http.StatusInternalServerError

		switch loginError.(type) {
		case dbc.NoResultsError:
			msg = "Invalid Username or Password"
			errCode = http.StatusBadRequest
		case dbc.DBError:
			msg = "Server Error"
			errCode = http.StatusInternalServerError
		case NonceError:
			msg = "Invalid Nonce"
			errCode = http.StatusBadRequest
		case JWTError:
			msg = "Server Encountered an Error While Generating JWT"
			errCode = http.StatusInternalServerError
		}

		ctx.JSON(
			errCode,
			gin.H{"error": msg},
		)
		return
	}

	ctx.JSON(200, gin.H{
		"token": token,
	})
}

// Prints the RSA Public Key for JWT verification
func (as *AuthServer) getPublicKeyRoute(ctx *gin.Context) {
	ctx.String(200, os.Getenv(RSA_PUBLIC_KEY))
}

func (as *AuthServer) addUser(ctx *gin.Context) {
	var header AdminHeader

	if headerErr := ctx.ShouldBindHeader(&header); headerErr != nil {
		ctx.JSON(
			http.StatusBadRequest,
			gin.H{"error": "Invalid Authorization Token"},
		)
		return
	}

	_, jwtErr := validateJWT(header.Token)

	if jwtErr != nil {
		ctx.JSON(
			http.StatusBadRequest,
			gin.H{"error": "Invalid Authorization Token"},
		)
		return
	}

	ctx.JSON(200, gin.H{
		"token": "token",
	})
	// var addUserBody AddUserBody
}

func (as *AuthServer) editUser(ctx *gin.Context) {}
