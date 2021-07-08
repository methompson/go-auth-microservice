package authServer

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
)

type AuthServer struct {
	AuthController AuthController
	GinEngine      *gin.Engine
	scheduled      chan bool
}

func StartServer() {
	loadEnvErr := LoadEnvVariables()

	if loadEnvErr != nil {
		log.Fatal(loadEnvErr.Error())
	}

	checkEnvErr := CheckEnvVariables()

	if checkEnvErr != nil {
		log.Fatal(checkEnvErr.Error())
	}

	authServer := makeNewServer()
	authServer.scheduleNonceCleanout()

	authServer.setRoutes()

	// The Run command blocks logging, so we just run it and nothing after.
	authServer.runServer()
}

func makeNewServer() AuthServer {
	mdbc, err := MakeMongoDbController()

	if err != nil {
		log.Fatal(err.Error())
	}

	initDbErr := mdbc.InitDatabase()

	if initDbErr != nil {
		log.Fatal("Error Initializing Database", initDbErr.Error())
	}

	engine := gin.Default()

	authServer := AuthServer{
		AuthController{mdbc},
		engine,
		make(chan bool),
	}

	// authServer.scheduled <- false

	return authServer
}

func (as AuthServer) runServer() {
	as.GinEngine.Run()
}

// Every 5 minutes, we'll clean up the Nonces
func (as AuthServer) scheduleNonceCleanout() {
	go func() {
		time.Sleep(5 * time.Minute)

		as.AuthController.RemoveOldNonces()

		as.scheduleNonceCleanout()
	}()
}
