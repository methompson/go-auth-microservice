package authServer

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	dbc "methompson.com/auth-microservice/authServer/dbController"
	mdbc "methompson.com/auth-microservice/authServer/mongoDbController"
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

	// We run this prior to creating a server
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	authServer := makeNewServer()

	// We run this after creating a server, but before setting routes
	if os.Getenv("GIN_MODE") == "release" {
		configureReleaseLogging(&authServer)
	}

	authServer.scheduleNonceCleanout()

	authServer.setRoutes()

	// The Run command blocks logging, so we just run it and nothing after.
	authServer.runServer()
}

func configureReleaseLogging(as *AuthServer) {
	as.GinEngine.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		(*as.AuthController.DBController).AddRequestLog(dbc.RequestLogData{
			TimeStamp:    param.TimeStamp,
			Type:         "request",
			ClientIP:     param.ClientIP,
			Method:       param.Method,
			Path:         param.Path,
			Protocol:     param.Request.Proto,
			StatusCode:   param.StatusCode,
			Latency:      param.Latency,
			UserAgent:    param.Request.UserAgent(),
			ErrorMessage: param.ErrorMessage,
		})

		return ""
	}))
}

func makeNewServer() AuthServer {
	mongoDbController, mongoDbControllerErr := mdbc.MakeMongoDbController(AUTH_DB_NAME)

	if mongoDbControllerErr != nil {
		log.Fatal(mongoDbControllerErr.Error())
	}

	initDbErr := mongoDbController.InitDatabase()

	if initDbErr != nil {
		log.Fatal("Error Initializing Database", initDbErr.Error())
	}

	engine := makeServer()

	var passedController dbc.DatabaseController = mongoDbController
	authServer := AuthServer{
		InitController(&passedController),
		engine,
		make(chan bool),
	}

	return authServer
}

func makeServer() *gin.Engine {
	if os.Getenv("GIN_MODE") == "release" {
		return gin.New()
	}

	return gin.Default()
}

func (as *AuthServer) runServer() {
	as.GinEngine.Run()
}

// Every 5 minutes, we'll clean up the Nonces
func (as *AuthServer) scheduleNonceCleanout() {
	go func() {
		time.Sleep(5 * time.Minute)

		as.AuthController.RemoveOldNonces()

		as.scheduleNonceCleanout()
	}()
}
