package authServer

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"methompson.com/auth-microservice/authServer/authCrypto"
	"methompson.com/auth-microservice/authServer/authUtils"
	"methompson.com/auth-microservice/authServer/constants"
	"methompson.com/auth-microservice/authServer/dbController"
	"methompson.com/auth-microservice/authServer/mongoDbController"
)

// The purpose of the AuthServer is to handle all aspects of serving data, handling
// requests and handling responses. This includes setting and configuring the main
// server object (the *gin.Engine object), handling all actions involving the body
// and headers of any requests, setting response codes and sending responses.
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
		errs := configureReleaseLogging(&authServer)

		if len(errs) > 0 {
			for _, err := range errs {
				print(err.Error() + "\n")
			}
		}
		addLogging(&authServer)

		addRecovery(&authServer)
	}

	authServer.scheduleNonceCleanout()

	authServer.setRoutes()

	// The Run command blocks console logging, so we just run it and nothing after.
	authServer.runServer()
}

func addLogging(as *AuthServer) {
	as.GinEngine.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		requestData := authUtils.RequestLogData{
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

		for _, logger := range as.AuthController.Loggers {
			l := *logger
			l.AddRequestLog(&requestData)
		}

		return ""
	}))
}

// TODO figure out recovery
func addRecovery(as *AuthServer) {
	as.GinEngine.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		msg := "Unknown Error"
		if err, ok := recovered.(string); ok {
			msg = fmt.Sprintf("error: %s", err)
			c.String(http.StatusInternalServerError, msg)
		}

		errorLog := authUtils.InfoLogData{
			Timestamp: time.Now(),
			Type:      "error",
			Message:   msg,
		}

		for _, logger := range as.AuthController.Loggers {
			l := *logger
			l.AddInfoLog(&errorLog)
		}

		c.AbortWithStatus(http.StatusInternalServerError)
	}))
}

func configureReleaseLogging(as *AuthServer) []error {
	errs := make([]error, 0)
	controller := &as.AuthController

	if os.Getenv(constants.DB_LOGGING) == "true" {
		// We set the logger to a database logger
		// First, we manipulate the pointers in order to add the DBController to the logger
		// in order to log release data to the database.
		var dbController authUtils.AuthLogger = *controller.DBController
		controller.AddLogger(&dbController)
	}

	if os.Getenv(constants.FILE_LOGGING) == "true" {
		// We can also log to a file
		var fileLogger authUtils.AuthLogger
		var fileLoggerErr error

		fileLogger, fileLoggerErr = authUtils.MakeNewFileLogger(os.Getenv(constants.FILE_LOGGING_PATH), "logs.log")

		if fileLoggerErr != nil {
			errs = append(errs, fileLoggerErr)
		}
		controller.AddLogger(&fileLogger)
	}

	if os.Getenv(constants.CONSOLE_LOGGING) == "true" {
		var consoleLogger authUtils.AuthLogger = &authUtils.ConsoleLogger{}

		controller.AddLogger(&consoleLogger)
	}

	return errs
}

func makeNewServer() AuthServer {
	mdbController, mdbControllerErr := mongoDbController.MakeMongoDbController(constants.AUTH_DB_NAME)

	if mdbControllerErr != nil {
		log.Fatal(mdbControllerErr.Error())
	}

	initDbErr := mdbController.InitDatabase()

	if initDbErr != nil {
		log.Fatal("Error Initializing Database", initDbErr.Error())
	}

	engine := makeServer()

	// First we assign the pointer-to MongoDbController of mongoDbController to
	// the variable indirect. Next, we assign that value to a variable of type
	// DatabaseController. Then we get the pointer-to DatabaseController and
	// assign that to cont. We can use pointer-to DatabaseController to run
	// InitController to initialize the AuthController.
	indirect := &mdbController
	var passedController dbController.DatabaseController = indirect
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

func (as *AuthServer) ExtractJWTFromHeader(ctx *gin.Context) (*authCrypto.JWTClaims, error) {
	var header AuthorizationHeader
	expiredTxt := "token is expired"
	invalidTxt := "invalid signing method"
	verificationTxt := "verification error"

	// No Token Error
	if headerErr := ctx.ShouldBindHeader(&header); headerErr != nil {
		return nil, authCrypto.NewJWTError("missing jwt from header")
	}

	claims, jwtErr := authCrypto.ValidateJWT(header.Token)

	// Expired Token Error
	// Invalid Signing Method Error
	// Verificatin error
	if jwtErr != nil {
		errTxt := strings.ToLower(jwtErr.Error())

		var returnErr error
		if strings.Contains(errTxt, expiredTxt) {
			returnErr = authCrypto.NewExpiredJWTError(jwtErr.Error())
		} else if strings.Contains(errTxt, invalidTxt) || strings.Contains(errTxt, verificationTxt) {
			returnErr = authCrypto.NewJWTError(jwtErr.Error())
		} else {
			returnErr = authCrypto.NewJWTError(jwtErr.Error())
		}

		return nil, returnErr
	}

	return claims, nil
}
