package authServer

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	au "methompson.com/auth-microservice/authServer/authUtils"
	dbc "methompson.com/auth-microservice/authServer/dbController"
	mdbc "methompson.com/auth-microservice/authServer/mongoDbController"
)

type AuthServer struct {
	AuthController AuthController
	GinEngine      *gin.Engine
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

	// We run this prior to creating a server. Any gin engine created prior
	// to running SetMode won't include this configuration.
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	authServer := makeNewServer()

	// We run this after creating a server, but before setting routes. Any
	// route set BEFORE this won't actually use this.
	if os.Getenv("GIN_MODE") == "release" {
		configureReleaseLogging(&authServer)
		fmt.Printf("Configured. Length: %d\n", len(authServer.AuthController.Loggers))
	}

	addLogging(&authServer)

	authServer.scheduleNonceCleanout()

	authServer.setRoutes()

	// The Run command blocks logging, so we just run it and nothing after.
	authServer.runServer()
}

func addLogging(as *AuthServer) {
	as.GinEngine.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		requestData := au.RequestLogData{
			Timestamp:    param.TimeStamp,
			Type:         "request",
			ClientIP:     param.ClientIP,
			Method:       param.Method,
			Path:         param.Path,
			Protocol:     param.Request.Proto,
			StatusCode:   param.StatusCode,
			Latency:      param.Latency,
			UserAgent:    param.Request.UserAgent(),
			ErrorMessage: param.ErrorMessage,
		}

		fmt.Printf("Logging: %d\n", len(as.AuthController.Loggers))

		for _, logger := range as.AuthController.Loggers {
			l := *logger
			l.AddRequestLog(&requestData)
		}

		return ""
	}))
}

func configureReleaseLogging(as *AuthServer) error {
	controller := &as.AuthController

	logErr := (*controller.DBController).AddInfoLog(&au.InfoLogData{
		Timestamp: time.Now(),
		Type:      "info",
		Message:   "Starting DB Logging",
	})

	if logErr == nil {
		// First, we manipulate the pointers in order to add the DBController to the logger
		// in order to log release data to the database.
		var dbController au.AuthLogger = *controller.DBController
		controller.AddLogger(&dbController)
		return nil
	}

	return logErr

	// We can also log to a file
	// var fileLogger au.AuthLogger = au.MakeNewFileLogger("logs/logs/logs", "logs.log")
	// controller.AddLogger(&fileLogger)
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

	// First we assign the pointer-to MongoDbController of mongoDbController to
	// the variable indirect. Next, we assign that value to a variable of type
	// DatabaseController. Then we get the pointer-to DatabaseController and
	// assign that to cont. We can use pointer-to DatabaseController to run
	// InitController to initialize the AuthController.
	indirect := &mongoDbController
	var passedController dbc.DatabaseController = indirect
	cont := &passedController

	authServer := AuthServer{
		AuthController: InitController(cont),
		GinEngine:      engine,
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
