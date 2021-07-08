package authServerTest

import (
	"fmt"
	"testing"

	"methompson.com/auth-microservice/authServer"
)

func TestInitControllerWillMakeAndReturnAuthController(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	ac := authServer.InitController(tdbc)

	if ac.DBController != tdbc {
		t.Fatalf("DBController not set correctly")
	}
}

func TestLogUserInFailsIfHashedNonceFails(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	ac := authServer.InitController(tdbc)

	body := authServer.LoginBody{
		Username: "test",
		Password: "test",
		Nonce:    "failure",
	}
	ctx := MakeTestContext()

	_, loginError := ac.LogUserIn(body, ctx)

	if loginError == nil {
		t.Fatalf("logUserIn should fail, but err is null")
	}

	switch loginError.(type) {
	case authServer.JWTError:
		t.Fatalf("loginError should be a NonceError. it's a JWTError")
	case authServer.NoDocumentError:
		t.Fatalf("loginError should be a NonceError. it's a NoDocumentError")
	case authServer.DBError:
		t.Fatalf("loginError should be a NonceError. it's a DBError")
	case authServer.NonceError:
		// t.Fatalf("loginError should be a NonceError. it's a NonceError")
		// It Passed!
	default:
		t.Fatalf("loginError should be a NonceError. it's a generic error")
	}
}

func TestLogUserInFailsIfCheckNonceFailsWithNonceError(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	tdbc.nonceDocErr = authServer.NewNonceError("")
	ac := authServer.InitController(tdbc)

	body := authServer.LoginBody{
		Username: "test",
		Password: "test",
		Nonce:    "MQ==", // Base64 for single character "1"
	}
	ctx := MakeTestContext()

	_, loginError := ac.LogUserIn(body, ctx)

	if loginError == nil {
		t.Fatalf("logUserIn should fail, but err is null")
	}

	switch loginError.(type) {
	case authServer.JWTError:
		t.Fatalf("loginError should be a NonceError. it's a JWTError")
	case authServer.NoDocumentError:
		t.Fatalf("loginError should be a NonceError. it's a NoDocumentError")
	case authServer.DBError:
		t.Fatalf("loginError should be a NonceError. it's a DBError")
	case authServer.NonceError:
		// It Passed!
	default:
		t.Fatalf("loginError should be a NonceError. it's a generic error")
	}
}

func TestLogUserInFailsIfCheckNonceFailsWithDbError(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	tdbc.nonceDocErr = authServer.NewDBError("")
	ac := authServer.InitController(tdbc)

	body := authServer.LoginBody{
		Username: "test",
		Password: "test",
		Nonce:    "MQ==", // Base64 for single character "1"
	}
	ctx := MakeTestContext()

	_, loginError := ac.LogUserIn(body, ctx)

	if loginError == nil {
		t.Fatalf("logUserIn should fail, but err is null")
	}

	switch loginError.(type) {
	case authServer.JWTError:
		t.Fatalf("loginError should be a NonceError. it's a JWTError")
	case authServer.NoDocumentError:
		t.Fatalf("loginError should be a NonceError. it's a NoDocumentError")
	case authServer.DBError:
		// t.Fatalf("loginError should be a NonceError. it's a DBError")
		// It Passed!
	case authServer.NonceError:
		t.Fatalf("loginError should be a NonceError. it's a NonceError")
	default:
		t.Fatalf("loginError should be a NonceError. it's a generic error")
	}
}

func TestLogUserInFailsIfGetUserByUsernameFailsWithNoDocError(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	tdbc.userDocErr = authServer.NewNoDocError("")
	ac := authServer.InitController(tdbc)

	body := authServer.LoginBody{
		Username: "test",
		Password: "test",
		Nonce:    "MQ==", // Base64 for single character "1"
	}
	ctx := MakeTestContext()

	_, loginError := ac.LogUserIn(body, ctx)

	if loginError == nil {
		t.Fatalf("logUserIn should fail, but err is null")
	}

	switch loginError.(type) {
	case authServer.JWTError:
		t.Fatalf("loginError should be a NonceError. it's a JWTError")
	case authServer.NoDocumentError:
		// t.Fatalf("loginError should be a NonceError. it's a NoDocumentError")
		// It Passed!
	case authServer.DBError:
		t.Fatalf("loginError should be a NonceError. it's a DBError")
	case authServer.NonceError:
		t.Fatalf("loginError should be a NonceError. it's a NonceError")
	default:
		t.Fatalf("loginError should be a NonceError. it's a generic error")
	}
}

func TestLogUserInFailsIfGetUserByUsernameFailsWithDBError(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	tdbc.userDocErr = authServer.NewDBError("")
	ac := authServer.InitController(tdbc)

	body := authServer.LoginBody{
		Username: "test",
		Password: "test",
		Nonce:    "MQ==", // Base64 for single character "1"
	}
	ctx := MakeTestContext()

	_, loginError := ac.LogUserIn(body, ctx)

	if loginError == nil {
		t.Fatalf("logUserIn should fail, but err is null")
	}

	switch loginError.(type) {
	case authServer.JWTError:
		t.Fatalf("loginError should be a NonceError. it's a JWTError")
	case authServer.NoDocumentError:
		t.Fatalf("loginError should be a NonceError. it's a NoDocumentError")
	case authServer.DBError:
		// t.Fatalf("loginError should be a NonceError. it's a DBError")
		// It Passed!
	case authServer.NonceError:
		t.Fatalf("loginError should be a NonceError. it's a NonceError")
	default:
		t.Fatalf("loginError should be a NonceError. it's a generic error")
	}
}

func TestLogUserInFailsIfGenerateJWTFails(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	ac := authServer.InitController(tdbc)

	body := authServer.LoginBody{
		Username: "test",
		Password: "test",
		Nonce:    "MQ==", // Base64 for single character "1"
	}
	ctx := MakeTestContext()

	_, loginError := ac.LogUserIn(body, ctx)

	if loginError == nil {
		t.Fatalf("logUserIn should fail, but err is null")
	}

	correctErr := "JWTError"
	switch loginError.(type) {
	case authServer.JWTError:
		// It Passed!
		// t.Fatalf(fmt.Sprint("loginError should be a ", correctErr, ". it's a JWTError"))
	case authServer.NoDocumentError:
		t.Fatalf(fmt.Sprint("loginError should be a ", correctErr, ". it's a NoDocumentError"))
	case authServer.DBError:
		t.Fatalf(fmt.Sprint("loginError should be a ", correctErr, ". it's a DBError"))
	case authServer.NonceError:
		t.Fatalf(fmt.Sprint("loginError should be a ", correctErr, ". it's a NonceError"))
	default:
		t.Fatalf(fmt.Sprint("loginError should be a ", correctErr, ". it's a generic error"))
	}
}
