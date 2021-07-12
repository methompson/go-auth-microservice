package authServerTest

import (
	"fmt"
	// "os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"methompson.com/auth-microservice/authServer"
)

func Test_Time(t *testing.T) {
	now := time.Now()

	add1 := now.Add(time.Minute * 5).Unix()
	add2 := now.Unix() + (60 * 5)

	if add1 != add2 {
		t.Fatalf("Not the same time")
	}

	sub1 := now.Add(time.Minute * -5).Unix()
	sub2 := now.Unix() - (60 * 5)

	if sub1 != sub2 {
		t.Fatalf("Not the same time")
	}

	sub3 := time.Minute * -5
	sub4 := -1 * (time.Minute * 5)

	if sub3 != sub4 {
		t.Fatalf("Not the same time")
	}
}

func Test_InitControllerWillMakeAndReturnAuthController(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

	if *ac.DBController != tdbc {
		t.Fatalf("DBController not set correctly")
	}
}

func Test_LogUserInFailsIfHashedNonceFails(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

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

	errType := ""
	switch loginError.(type) {
	case authServer.CryptoKeyError:
		errType = "CryptoKeyError"
	case authServer.JWTError:
		errType = "JWTError"
	case authServer.NoDocumentError:
		errType = "NoDocumentError"
	case authServer.DBError:
		errType = "DBError"
	case authServer.NonceError:
		// It Passed!
		// errType = "NonceError"
	default:
		errType = "generic error"
	}

	if len(errType) > 0 {
		t.Fatalf(fmt.Sprint("loginError should be a NonceError. it's a ", errType, ". ", loginError.Error()))
	}
}

func Test_LogUserInFailsIfCheckNonceFailsWithNonceError(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	tdbc.SetNonceDocErr(authServer.NewNonceError(""))
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

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

	errType := ""
	switch loginError.(type) {
	case authServer.CryptoKeyError:
		errType = "CryptoKeyError"
	case authServer.JWTError:
		errType = "JWTError"
	case authServer.NoDocumentError:
		errType = "NoDocumentError"
	case authServer.DBError:
		errType = "DBError"
	case authServer.NonceError:
		// It Passed!
		// errType = "NonceError"
	default:
		errType = "generic error"
	}

	if len(errType) > 0 {
		t.Fatalf(fmt.Sprint("loginError should be a NonceError. it's a ", errType, ". ", loginError.Error()))
	}
}

func Test_LogUserInFailsIfCheckNonceFailsWithDbError(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	tdbc.SetNonceDocErr(authServer.NewDBError(""))
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

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

	errType := ""
	switch loginError.(type) {
	case authServer.CryptoKeyError:
		errType = "CryptoKeyError"
	case authServer.JWTError:
		errType = "JWTError"
	case authServer.NoDocumentError:
		errType = "NoDocumentError"
	case authServer.DBError:
		// It Passed!
		// errType = "DBError"
	case authServer.NonceError:
		errType = "NonceError"
	default:
		errType = "generic error"
	}

	if len(errType) > 0 {
		t.Fatalf(fmt.Sprint("loginError should be a DBError. it's a ", errType, ". ", loginError.Error()))
	}
}

func Test_LogUserInFailsIfGetUserByUsernameFailsWithNoDocError(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	tdbc.SetUserDocErr(authServer.NewNoDocError(""))
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

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

	errType := ""
	switch loginError.(type) {
	case authServer.CryptoKeyError:
		errType = "CryptoKeyError"
	case authServer.JWTError:
		errType = "JWTError"
	case authServer.NoDocumentError:
		// It Passed!
		// errType = "NoDocumentError"
	case authServer.DBError:
		errType = "DBError"
	case authServer.NonceError:
		errType = "NonceError"
	default:
		errType = "generic error"
	}

	if len(errType) > 0 {
		t.Fatalf(fmt.Sprint("loginError should be a NoDocumentError. it's a ", errType, ". ", loginError.Error()))
	}
}

func Test_LogUserInFailsIfGetUserByUsernameFailsWithDBError(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	tdbc.SetUserDocErr(authServer.NewDBError(""))
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

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

	errType := ""
	switch loginError.(type) {
	case authServer.CryptoKeyError:
		errType = "CryptoKeyError"
	case authServer.JWTError:
		errType = "JWTError"
	case authServer.NoDocumentError:
		errType = "NoDocumentError"
	case authServer.DBError:
		// It Works
		// errType = "DBError"
	case authServer.NonceError:
		errType = "NonceError"
	default:
		errType = "generic error"
	}

	if len(errType) > 0 {
		t.Fatalf(fmt.Sprint("loginError should be a DBError. it's a ", errType, ". ", loginError.Error()))
	}
}

func Test_LogUserInFailsIfGenerateJWTFails(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

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

	errType := ""
	switch loginError.(type) {
	case authServer.CryptoKeyError:
		// It Passed!
		// errType = "CryptoKeyError"
	case authServer.JWTError:
		errType = "JWTError"
	case authServer.NoDocumentError:
		errType = "NoDocumentError"
	case authServer.DBError:
		errType = "DBError"
	case authServer.NonceError:
		errType = "NonceError"
	default:
		errType = "generic error"
	}

	if len(errType) > 0 {
		t.Fatalf(fmt.Sprint("loginError should be a CryptoKeyError. it's a ", errType, ". ", loginError.Error()))
	}
}

func Test_LogUserInWillGenerateAJWT(t *testing.T) {
	username, password, email := "test", "test", "test"

	PrepTestRSAKeys()

	tdbc := MakeBlankTestDbController()
	tdbc.SetUserDoc(authServer.UserDocument{
		Username: username,
		Email:    email,
		Enabled:  true,
	})

	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

	expEarlierTime := authServer.GetJWTExpirationTime()

	loginBody := authServer.LoginBody{
		Username: username,
		Password: password,
		Nonce:    "MQ==", // Base64 for single character "1"
	}
	ctx := MakeTestContext()
	result, loginError := ac.LogUserIn(loginBody, ctx)

	if loginError != nil {
		t.Fatalf(fmt.Sprint("logUserIn should not fail", loginError))
	}

	token, tokenErr := jwt.Parse(result, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("Invalid JWT Signature")
		}

		return authServer.GetRSAPublicKey()
	})

	if tokenErr != nil {
		t.Fatalf(fmt.Sprint("tokenErr should be nil: ", tokenErr.Error()))
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["username"] != "test" {
			t.Fatalf("Invalid username claim")
		}
		if claims["email"] != "test" {
			t.Fatalf("Invalid email claim")
		}

		expFloat := claims["exp"].(float64)
		exp := int64(expFloat)

		if !ok {
			t.Fatalf("jwt not ok")
		}

		// expEarlierTime was calculated before the JWT is generated. We expect
		// the actual expiration time to be either the same or larger (i.e. in
		// the future) than the earlier time we calculated.
		if exp < expEarlierTime {
			t.Fatalf("Invalid expiration time")
		}
	} else {
		t.Fatalf("Invalid JWT Token")
	}
}

func Test_CheckNonceHashFailsIfGetNonceFails(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	tdbc.SetNonceDocErr(authServer.NewNonceError(""))
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

	ctx := MakeTestContext()

	checkNonceError := ac.CheckNonceHash("", ctx)

	if checkNonceError == nil {
		t.Fatalf("CheckNonceHash should fail, but checkNonceError is nil")
	}

	errType := ""
	switch checkNonceError.(type) {
	case authServer.CryptoKeyError:
		errType = "CryptoKeyError"
	case authServer.JWTError:
		errType = "JWTError"
	case authServer.NoDocumentError:
		errType = "NoDocumentError"
	case authServer.DBError:
		errType = "DBError"
	case authServer.NonceError:
		// It Passed!
		// errType = "NonceError"
	default:
		errType = "generic error"
	}

	if len(errType) > 0 {
		t.Fatalf(fmt.Sprint("loginError should be a NonceError. it's a ", errType, ". ", checkNonceError.Error()))
	}
}

func Test_CheckNonceHashSucceedsIfGetNonceReturnsNoError(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

	ctx := MakeTestContext()

	checkNonceError := ac.CheckNonceHash("", ctx)

	if checkNonceError != nil {
		t.Fatalf(fmt.Sprint("CheckNonceHash should succeed, but checkNonceError is not nil", checkNonceError.Error()))
	}
}

func Test_GenerateNonceFailsIfAddNonceFails(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	tdbc.SetAddNonceErr(authServer.NewDBError(""))
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

	ctx := MakeTestContext()

	_, nonceError := ac.GenerateNonce(ctx)

	if nonceError == nil {
		t.Fatalf("CheckNonceHash should fail, but checkNonceError is nil")
	}

	errType := ""
	switch nonceError.(type) {
	case authServer.CryptoKeyError:
		errType = "CryptoKeyError"
	case authServer.JWTError:
		errType = "JWTError"
	case authServer.NoDocumentError:
		errType = "NoDocumentError"
	case authServer.DBError:
		// It Passed!
		// errType = "DBError"
	case authServer.NonceError:
		errType = "NonceError"
	default:
		errType = "generic error"
	}

	if len(errType) > 0 {
		t.Fatalf(fmt.Sprint("loginError should be a DBError. it's a ", errType, ". ", nonceError.Error()))
	}
}

func Test_GenerateNonceShouldReturnARandomString(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

	ctx := MakeTestContext()

	nonce, nonceError := ac.GenerateNonce(ctx)

	if nonceError != nil {
		t.Fatalf(fmt.Sprint("CheckNonceHash should not fail, but checkNonceError is not nil. ", nonceError.Error()))
	}

	if len(nonce) == 0 {
		t.Fatalf("nonce should have a length greater than zero")
	}
}

func Test_RemoveOldNoncesFailsIfRemoveOldNoncesFails(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	tdbc.SetRemoveOldNoncesErr(authServer.NewDBError(""))
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

	removeError := ac.RemoveOldNonces()

	if removeError == nil {
		t.Fatalf("CheckNonceHash should fail, but checkNonceError is nil")
	}

	errType := ""
	switch removeError.(type) {
	case authServer.CryptoKeyError:
		errType = "CryptoKeyError"
	case authServer.JWTError:
		errType = "JWTError"
	case authServer.NoDocumentError:
		errType = "NoDocumentError"
	case authServer.DBError:
		// It Passed!
		// errType = "DBError"
	case authServer.NonceError:
		errType = "NonceError"
	default:
		errType = "generic error"
	}

	if len(errType) > 0 {
		t.Fatalf(fmt.Sprint("removeError should be a DBError. it's a ", errType, ". ", removeError.Error()))
	}
}

func Test_RemoveOldNoncesSucceedsIfErrIsNil(t *testing.T) {
	tdbc := MakeBlankTestDbController()
	var passedController authServer.DatabaseController = tdbc
	ac := authServer.InitController(&passedController)

	removeError := ac.RemoveOldNonces()

	if removeError != nil {
		t.Fatalf(fmt.Sprint("CheckNonceHash should not fail, but checkNonceError is not nil. ", removeError.Error()))
	}
}
