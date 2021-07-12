package authServer

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

type AuthServer struct {
	AuthController AuthController
	GinEngine      *gin.Engine
	scheduled      chan bool
}

func StartServer() {
	flag.Parse()
	loadEnvErr := LoadEnvVariables()

	if loadEnvErr != nil {
		log.Fatal(loadEnvErr.Error())
	}

	checkEnvErr := CheckEnvVariables()

	if checkEnvErr != nil {
		log.Fatal(checkEnvErr.Error())
	}

	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	authServer := makeNewServer()
	authServer.scheduleNonceCleanout()

	authServer.setRoutes()

	// The Run command blocks logging, so we just run it and nothing after.
	authServer.runServer()
}

func makeNewServer() AuthServer {
	mongoDbController, mongoDbControllerErr := MakeMongoDbController()

	if mongoDbControllerErr != nil {
		log.Fatal(mongoDbControllerErr.Error())
	}

	initDbErr := mongoDbController.InitDatabase()

	if initDbErr != nil {
		log.Fatal("Error Initializing Database", initDbErr.Error())
	}
	configureLogging()

	engine := gin.Default()

	var passedController DatabaseController = mongoDbController
	authServer := AuthServer{
		InitController(&passedController),
		engine,
		make(chan bool),
	}

	return authServer
}

func configureLogging() {
	gin.DisableConsoleColor()
	if os.Getenv("GIN_MODE") == "release" {
		fmt.Println("Release Mode")

		// Logging to a file.
		f, _ := os.Create("gin.log")
		gin.DefaultWriter = io.MultiWriter(f)
	}
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
