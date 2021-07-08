package authServerTest

import (
	"testing"

	"methompson.com/auth-microservice/authServer"
)

func TestLoadAndCheckEnvVariables(t *testing.T) {
	err := authServer.CheckEnvVariables()

	// fmt.Println(err.Error())

	if err == nil {
		t.Fatalf("Error should not be nil")
	}
}
