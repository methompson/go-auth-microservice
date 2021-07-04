package authServer

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

type AuthServer struct {
	AuthDataController AuthController
	GinEngine          *gin.Engine
}

func StartServer() AuthServer {
	LoadAndCheckEnvVariables()

	as := makeNewServer()
	as.setRoutes()
	as.runServer()

	return as
}

func makeNewServer() AuthServer {
	mdbc := MakeMongoDbController()

	initDbErr := mdbc.InitDatabase()

	if initDbErr != nil {
		log.Fatal("Error Initializing Database", initDbErr)
	}

	engine := gin.Default()

	authServer := AuthServer{mdbc, engine}

	return authServer
}

func (as AuthServer) runServer() {
	as.GinEngine.Run()
}

func (as AuthServer) setRoutes() {
	as.GinEngine.GET("/", as.getHomeRoute)
	as.GinEngine.GET("/nonce", as.getNonceRoute)
	as.GinEngine.GET("/public-key", as.getPublicKeyRoute)

	as.GinEngine.POST("/login", as.postLoginRoute)
	as.GinEngine.POST("/verify-token", as.postVerifyTokenRoute)

}

func (as AuthServer) getHomeRoute(ctx *gin.Context) {
	ctx.Data(200, "text/html; charset=utf-8", make([]byte, 0))
}

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

func (as AuthServer) postVerifyTokenRoute(ctx *gin.Context) {
	ctx.JSON(200, gin.H{
		"verify": "verify",
	})
}

func (as AuthServer) getPublicKeyRoute(ctx *gin.Context) {
	ctx.String(200, os.Getenv(RSA_PUBLIC_KEY))
}
