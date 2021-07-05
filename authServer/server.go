package authServer

import (
	"log"

	"github.com/gin-gonic/gin"
)

type AuthServer struct {
	AuthDataController AuthController
	GinEngine          *gin.Engine
}

func StartServer() AuthServer {
	LoadAndCheckEnvVariables()

	authServer := makeNewServer()
	authServer.setRoutes()
	authServer.runServer()

	return authServer
}

func makeNewServer() AuthServer {
	mdbc, err := MakeMongoDbAuthController()

	if err != nil {
		log.Fatal(err.Error())
	}

	initDbErr := mdbc.InitDatabase()

	if initDbErr != nil {
		log.Fatal("Error Initializing Database", initDbErr.Error())
	}

	engine := gin.Default()

	authServer := AuthServer{mdbc, engine}

	return authServer
}

func (as AuthServer) runServer() {
	as.GinEngine.Run()
}
