package authServerTest

import (
	"os"
	"testing"

	"methompson.com/auth-microservice/authServer"
	"methompson.com/auth-microservice/authServer/constants"
)

func Test_LoadEnvVariables(t *testing.T) {}

func Test_CheckEnvVariables(t *testing.T) {
	t.Run("If no environment variables have been set, CheckEnvVariables should return an error", func(t *testing.T) {
		err := authServer.CheckEnvVariables()

		if err == nil {
			t.Fatalf("Error should not be nil")
		}
	})
	t.Run("When the environment variables are set, CheckEnvVariables will return nil", func(t *testing.T) {
		os.Setenv(constants.MONGO_DB_PASSWORD, "test")
		os.Setenv(constants.MONGO_DB_URL, "test")
		os.Setenv(constants.MONGO_DB_USERNAME, "test")

		err := authServer.CheckEnvVariables()

		if err != nil {
			t.Fatalf("Error should be nil: " + err.Error())
		}
	})
}

func Test_openAndSetRSAKeys(t *testing.T) {}

func Test_checkRSAKeys(t *testing.T) {}
