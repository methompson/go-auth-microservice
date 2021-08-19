package authServer

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"methompson.com/auth-microservice/authServer/authCrypto"
	"methompson.com/auth-microservice/authServer/authUtils"
	"methompson.com/auth-microservice/authServer/constants"
	"methompson.com/auth-microservice/authServer/dbController"
)

// setRoutes sets all of the routes for the Gin Server
func (as *AuthServer) setRoutes() {
	as.GinEngine.GET("/", as.getHomeRoute)
	as.GinEngine.GET("/nonce", as.getNonceRoute)
	as.GinEngine.GET("/public-key", as.getPublicKeyRoute)

	as.GinEngine.POST("/login", as.postLoginRoute)
	as.GinEngine.POST("/add-user", as.postAddUserRoute)
	as.GinEngine.POST("/edit-user", as.postEditUserRoute)
	as.GinEngine.POST("/edit-user-password", as.postEditUserPasswordRoute)
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
		case dbController.DBError:
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
		var msg string
		var errCode int

		switch loginError.(type) {
		case dbController.NoResultsError:
			msg = "Invalid Username or Password"
			errCode = http.StatusBadRequest
		case dbController.DBError:
			msg = "Server Error"
			errCode = http.StatusInternalServerError
		case authUtils.NonceError:
			msg = "Invalid Nonce"
			errCode = http.StatusBadRequest
		case authCrypto.JWTError:
			msg = "Server Encountered an Error While Generating JWT"
			errCode = http.StatusInternalServerError
		case LoginError:
			msg = "Invalid username or password"
			errCode = http.StatusUnauthorized
		default:
			msg = "Unknown Error"
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
	ctx.String(200, os.Getenv(constants.RSA_PUBLIC_KEY))
}

// TODO Log all errors
func (as *AuthServer) postAddUserRoute(ctx *gin.Context) {
	// Check the user's authorization token.
	claims, claimsErr := as.ExtractJWTFromHeader(ctx)
	if claimsErr != nil {
		var errMsg string
		var statusCode int

		switch claimsErr.(type) {
		case authCrypto.ExpiredJWTError:
			errMsg = "Expired authorization token"
			statusCode = http.StatusUnauthorized
		case authCrypto.JWTError:
			errMsg = "Not authorized"
			statusCode = http.StatusUnauthorized
		default:
			errMsg = "Invalid authorization token"
			statusCode = http.StatusBadRequest
		}

		ctx.JSON(
			statusCode,
			gin.H{"error": errMsg},
		)
		return
	}

	if !claims.Admin {
		ctx.JSON(
			http.StatusUnauthorized,
			gin.H{"error": "Not Authorized"},
		)
		return
	}

	// Extract data from the body of the request.
	var body AddUserBody

	if bindJsonErr := ctx.ShouldBindJSON(&body); bindJsonErr != nil {
		ctx.JSON(
			http.StatusBadRequest,
			gin.H{"error": "missing required values"},
			// gin.H{"error": bindJsonErr.Error()},
		)
		return
	}

	addUserErr := as.AuthController.AddNewUser(body, ctx)

	if addUserErr != nil {

		var errMsg string
		var statusCode int

		switch addUserErr.(type) {
		case authUtils.NonceError:
			errMsg = "Invalid nonce"
			statusCode = http.StatusBadRequest
		case dbController.DBError:
			errMsg = "Internal server error"
			statusCode = http.StatusInternalServerError
		case dbController.DuplicateEntryError:
			errMsg = addUserErr.Error()
			statusCode = http.StatusBadRequest
		default:
			errMsg = "Error adding user"
			statusCode = http.StatusBadRequest
		}

		ctx.JSON(
			statusCode,
			gin.H{"error": errMsg},
		)
		return
	}

	ctx.Status(200)
}

// postEditUserRoute is the POST /edit-user route. This route handles updating
// user information. Admin users are allowed to edit any user's information.
// Otherwise, regular users can update their own information.
func (as *AuthServer) postEditUserRoute(ctx *gin.Context) {
	// Check the user's authorization token. We want to make sure it exists.
	claims, claimsErr := as.ExtractJWTFromHeader(ctx)

	// We determine if there are any issues with the claims. If it expired or is not
	// valid.
	if claimsErr != nil {
		var errMsg string
		var statusCode int

		switch claimsErr.(type) {
		case authCrypto.ExpiredJWTError:
			errMsg = "Expired authorization token"
			statusCode = http.StatusUnauthorized
		case authCrypto.JWTError:
			errMsg = "Not authorized"
			statusCode = http.StatusUnauthorized
		default:
			errMsg = "Invalid authorization token"
			statusCode = http.StatusBadRequest
		}

		ctx.JSON(
			statusCode,
			gin.H{"error": errMsg},
		)
		return
	}

	// We extract the data from the request body and check that the body is OK
	var body *EditUserBody = &EditUserBody{}
	if bindJsonErr := ctx.ShouldBindJSON(body); bindJsonErr != nil {
		ctx.JSON(
			http.StatusBadRequest,
			gin.H{"error": "Missing required values"},
		)
		return
	}

	// Perform the actual edit
	editUserErr := as.AuthController.EditUser(body, claims, ctx)

	if editUserErr != nil {
		var errMsg string
		var statusCode int

		switch editUserErr.(type) {
		case UnauthorizedError:
			errMsg = "Not authorized to perform this action"
			statusCode = http.StatusUnauthorized
		case authUtils.NonceError:
			errMsg = "Invalid nonce"
			statusCode = http.StatusBadRequest
		case authCrypto.JWTError:
			errMsg = "Not authorized"
			statusCode = http.StatusUnauthorized
		case dbController.DuplicateEntryError:
			errMsg = editUserErr.Error()
			statusCode = http.StatusBadRequest
		case dbController.InvalidInputError:
			errMsg = editUserErr.Error()
			statusCode = http.StatusBadRequest
		default:
			errMsg = "Error editing user"
			statusCode = http.StatusBadRequest
		}

		ctx.JSON(
			statusCode,
			gin.H{"error": errMsg},
		)
		return
	}

	ctx.Status(200)
}

func (as *AuthServer) postEditUserPasswordRoute(ctx *gin.Context) {
	// Check the user's authorization token. We want to make sure it exists.
	claims, claimsErr := as.ExtractJWTFromHeader(ctx)

	// We determine if there are any issues with the claims. If it expired or is not
	// valid.
	if claimsErr != nil {
		var errMsg string
		var statusCode int

		switch claimsErr.(type) {
		case authCrypto.ExpiredJWTError:
			errMsg = "Expired authorization token"
			statusCode = http.StatusUnauthorized
		case authCrypto.JWTError:
			errMsg = "Not authorized"
			statusCode = http.StatusUnauthorized
		default:
			errMsg = "Invalid authorization token"
			statusCode = http.StatusBadRequest
		}

		ctx.JSON(
			statusCode,
			gin.H{"error": errMsg},
		)
		return
	}

	// Extract data from the body of the request. We'll do this before the admin
	// check so that we can compare the id from the body to the id in the header
	var body *EditPasswordBody = &EditPasswordBody{}
	if bindJsonErr := ctx.ShouldBindJSON(body); bindJsonErr != nil {
		ctx.JSON(
			http.StatusBadRequest,
			gin.H{"error": "missing required values"},
		)
		return
	}

	editPassErr := as.AuthController.EditUserPassword(body, claims, ctx)

	if editPassErr != nil {
		var errMsg string
		var statusCode int

		switch editPassErr.(type) {
		case UnauthorizedError:
			errMsg = "Not authorized to perform this action"
			statusCode = http.StatusUnauthorized
		case authUtils.NonceError:
			errMsg = "Invalid nonce"
			statusCode = http.StatusBadRequest
		case authCrypto.JWTError:
			errMsg = "Not authorized"
			statusCode = http.StatusUnauthorized
		case dbController.InvalidInputError:
			errMsg = editPassErr.Error()
			statusCode = http.StatusBadRequest
		default:
			errMsg = "Error editing user"
			statusCode = http.StatusBadRequest
		}

		ctx.JSON(
			statusCode,
			gin.H{"error": errMsg},
		)
		return
	}

	ctx.Status(200)
}
