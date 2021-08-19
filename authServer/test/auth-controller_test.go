package authServerTest

import (
	"fmt"
	// "os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"methompson.com/auth-microservice/authServer"

	mocks "methompson.com/auth-microservice/authServer/test/authServerMocks"

	"methompson.com/auth-microservice/authServer/authCrypto"
	"methompson.com/auth-microservice/authServer/authUtils"
	"methompson.com/auth-microservice/authServer/dbController"
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

func Test_InitController(t *testing.T) {
	t.Run("InitController Will Make and Return an Auth Controller", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		if *ac.DBController != tdbc {
			t.Fatalf("DBController not set correctly")
		}
	})
}

func Test_LogUserIn(t *testing.T) {
	t.Run("LogUserIn fails if hashed nonce fails", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		body := authServer.LoginBody{
			Username: "test",
			Password: "test",
			Nonce:    "failure",
		}
		ctx := mocks.MakeTestContext()

		_, loginError := ac.LogUserIn(body, ctx)

		if loginError == nil {
			t.Fatalf("logUserIn should fail, but err is null")
		}

		errType := ""
		switch loginError.(type) {
		case authCrypto.CryptoKeyError:
			errType = "CryptoKeyError"
		case authCrypto.JWTError:
			errType = "JWTError"
		case dbController.NoResultsError:
			errType = "NoDocumentError"
		case dbController.DBError:
			errType = "DBError"
		case authUtils.NonceError:
			// It Passed!
			// errType = "NonceError"
		default:
			errType = "generic error"
		}

		if len(errType) > 0 {
			t.Fatalf(fmt.Sprint("loginError should be a NonceError. it's a ", errType, ". ", loginError.Error()))
		}
	})
	t.Run("LogUserIn fails if CheckNonce fails with NonceError", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		tdbc.SetNonceDocErr(authUtils.NewNonceError(""))

		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		body := authServer.LoginBody{
			Username: "test",
			Password: "test",
			Nonce:    "MQ==", // Base64 for single character "1"
		}
		ctx := mocks.MakeTestContext()

		_, loginError := ac.LogUserIn(body, ctx)

		if loginError == nil {
			t.Fatalf("logUserIn should fail, but err is null")
		}

		errType := ""
		switch loginError.(type) {
		case authCrypto.CryptoKeyError:
			errType = "CryptoKeyError"
		case authCrypto.JWTError:
			errType = "JWTError"
		case dbController.NoResultsError:
			errType = "NoDocumentError"
		case dbController.DBError:
			errType = "DBError"
		case authUtils.NonceError:
			// It Passed!
			// errType = "NonceError"
		default:
			errType = "generic error"
		}

		if len(errType) > 0 {
			t.Fatalf(fmt.Sprint("loginError should be a NonceError. it's a ", errType, ". ", loginError.Error()))
		}
	})
	t.Run("LogUserIn fails if CheckNonce fails with DBError", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		tdbc.SetNonceDocErr(dbController.NewDBError(""))
		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		body := authServer.LoginBody{
			Username: "test",
			Password: "test",
			Nonce:    "MQ==", // Base64 for single character "1"
		}
		ctx := mocks.MakeTestContext()

		_, loginError := ac.LogUserIn(body, ctx)

		if loginError == nil {
			t.Fatalf("logUserIn should fail, but err is null")
		}

		errType := ""
		switch loginError.(type) {
		case authCrypto.CryptoKeyError:
			errType = "CryptoKeyError"
		case authCrypto.JWTError:
			errType = "JWTError"
		case dbController.NoResultsError:
			errType = "NoDocumentError"
		case dbController.DBError:
			// It Passed!
			// errType = "DBError"
		case authUtils.NonceError:
			errType = "NonceError"
		default:
			errType = "generic error"
		}

		if len(errType) > 0 {
			t.Fatalf(fmt.Sprint("loginError should be a DBError. it's a ", errType, ". ", loginError.Error()))
		}
	})
	t.Run("LogUserIn fails if GetUserByUsername fails with NoDocError", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		tdbc.SetUserDocErr(dbController.NewNoResultsError(""))
		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		body := authServer.LoginBody{
			Username: "test",
			Password: "test",
			Nonce:    "MQ==", // Base64 for single character "1"
		}
		ctx := mocks.MakeTestContext()

		_, loginError := ac.LogUserIn(body, ctx)

		if loginError == nil {
			t.Fatalf("logUserIn should fail, but err is null")
		}

		errType := ""
		switch loginError.(type) {
		case authCrypto.CryptoKeyError:
			errType = "CryptoKeyError"
		case authCrypto.JWTError:
			errType = "JWTError"
		case dbController.NoResultsError:
			// It Passed!
			// errType = "NoDocumentError"
		case dbController.DBError:
			errType = "DBError"
		case authUtils.NonceError:
			errType = "NonceError"
		default:
			errType = "generic error"
		}

		if len(errType) > 0 {
			t.Fatalf(fmt.Sprint("loginError should be a NoDocumentError. it's a ", errType, ". ", loginError.Error()))
		}
	})
	t.Run("LogUserIn fails if GetUserByUsername fails with DBError", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		tdbc.SetUserDocErr(dbController.NewDBError(""))
		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		body := authServer.LoginBody{
			Username: "test",
			Password: "test",
			Nonce:    "MQ==", // Base64 for single character "1"
		}
		ctx := mocks.MakeTestContext()

		_, loginError := ac.LogUserIn(body, ctx)

		if loginError == nil {
			t.Fatalf("logUserIn should fail, but err is null")
		}

		errType := ""
		switch loginError.(type) {
		case authCrypto.CryptoKeyError:
			errType = "CryptoKeyError"
		case authCrypto.JWTError:
			errType = "JWTError"
		case dbController.NoResultsError:
			errType = "NoDocumentError"
		case dbController.DBError:
			// It Works
			// errType = "DBError"
		case authUtils.NonceError:
			errType = "NonceError"
		default:
			errType = "generic error"
		}

		if len(errType) > 0 {
			t.Fatalf(fmt.Sprint("loginError should be a DBError. it's a ", errType, ". ", loginError.Error()))
		}
	})
	t.Run("LogUserIn fails if GenerateJWT fails", func(t *testing.T) {
		username, password, email := "test", "test", "test"

		hashedPass, _ := authUtils.HashPassword(password)

		tdbc := mocks.MakeBlankTestDbController()
		tdbc.SetUserDoc(dbController.FullUserDocument{
			Username:     username,
			PasswordHash: hashedPass,
			Email:        email,
		})

		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		body := authServer.LoginBody{
			Username: username,
			Password: password,
			Nonce:    "MQ==", // Base64 for single character "1"
		}
		ctx := mocks.MakeTestContext()

		_, loginError := ac.LogUserIn(body, ctx)

		if loginError == nil {
			t.Fatalf("logUserIn should fail, but err is null")
		}

		errType := ""
		switch loginError.(type) {
		case authCrypto.CryptoKeyError:
			// It Passed!
			// errType = "CryptoKeyError"
		case authCrypto.JWTError:
			errType = "JWTError"
		case dbController.NoResultsError:
			errType = "NoDocumentError"
		case dbController.DBError:
			errType = "DBError"
		case authUtils.NonceError:
			errType = "NonceError"
		default:
			errType = "generic error"
		}

		if len(errType) > 0 {
			t.Fatalf(fmt.Sprint("loginError should be a CryptoKeyError, but it's a ", errType, ". ", loginError.Error()))
		}
	})
	t.Run("LogUserIn will generate a JWT", func(t *testing.T) {
		username, password, email := "test", "test", "test"
		hashedPass, _ := authUtils.HashPassword(password)

		mocks.PrepTestRSAKeys()

		tdbc := mocks.MakeBlankTestDbController()
		tdbc.SetUserDoc(dbController.FullUserDocument{
			Username:     username,
			Email:        email,
			Enabled:      true,
			PasswordHash: hashedPass,
		})

		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		expEarlierTime := authCrypto.GetJWTExpirationTime()

		loginBody := authServer.LoginBody{
			Username: username,
			Password: password,
			Nonce:    "MQ==", // Base64 for single character "1"
		}
		ctx := mocks.MakeTestContext()
		result, loginError := ac.LogUserIn(loginBody, ctx)

		if loginError != nil {
			t.Fatalf(fmt.Sprint("logUserIn should not fail", loginError))
		}

		token, tokenErr := jwt.Parse(result, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				t.Fatalf("Invalid JWT Signature")
			}

			return authCrypto.GetRSAPublicKey()
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
	})
}

func Test_CheckNonce(t *testing.T) {
	t.Run("CheckNonceHash fails if GetNonce fails", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		tdbc.SetNonceDocErr(authUtils.NewNonceError(""))
		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		ctx := mocks.MakeTestContext()

		checkNonceError := ac.CheckNonceHash("", ctx)

		if checkNonceError == nil {
			t.Fatalf("CheckNonceHash should fail, but checkNonceError is nil")
		}

		errType := ""
		switch checkNonceError.(type) {
		case authCrypto.CryptoKeyError:
			errType = "CryptoKeyError"
		case authCrypto.JWTError:
			errType = "JWTError"
		case dbController.NoResultsError:
			errType = "NoDocumentError"
		case dbController.DBError:
			errType = "DBError"
		case authUtils.NonceError:
			// It Passed!
			// errType = "NonceError"
		default:
			errType = "generic error"
		}

		if len(errType) > 0 {
			t.Fatalf(fmt.Sprint("loginError should be a NonceError. it's a ", errType, ". ", checkNonceError.Error()))
		}
	})
	t.Run("CheckNonceHash succeeds if GetNonce returns no error", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		ctx := mocks.MakeTestContext()

		checkNonceError := ac.CheckNonceHash("", ctx)

		if checkNonceError != nil {
			t.Fatalf(fmt.Sprint("CheckNonceHash should succeed, but checkNonceError is not nil", checkNonceError.Error()))
		}
	})
}

func Test_GenerateNonce(t *testing.T) {
	t.Run("GenerateNonce fails if AddNonce fails", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		tdbc.SetAddNonceErr(dbController.NewDBError(""))
		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		ctx := mocks.MakeTestContext()

		_, nonceError := ac.GenerateNonce(ctx)

		if nonceError == nil {
			t.Fatalf("CheckNonceHash should fail, but checkNonceError is nil")
		}

		errType := ""
		switch nonceError.(type) {
		case authCrypto.CryptoKeyError:
			errType = "CryptoKeyError"
		case authCrypto.JWTError:
			errType = "JWTError"
		case dbController.NoResultsError:
			errType = "NoDocumentError"
		case dbController.DBError:
			// It Passed!
			// errType = "DBError"
		case authUtils.NonceError:
			errType = "NonceError"
		default:
			errType = "generic error"
		}

		if len(errType) > 0 {
			t.Fatalf(fmt.Sprint("loginError should be a DBError. it's a ", errType, ". ", nonceError.Error()))
		}
	})
	t.Run("GenerateNonce should return a random string", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		ctx := mocks.MakeTestContext()

		nonce, nonceError := ac.GenerateNonce(ctx)

		if nonceError != nil {
			t.Fatalf(fmt.Sprint("CheckNonceHash should not fail, but checkNonceError is not nil. ", nonceError.Error()))
		}

		if len(nonce) == 0 {
			t.Fatalf("nonce should have a length greater than zero")
		}
	})
}

func Test_RemoveOldNonces(t *testing.T) {
	t.Run("RemoveOldNonces fails if DBController.RemoveOldNonces fails", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		tdbc.SetRemoveOldNoncesErr(dbController.NewDBError(""))
		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		removeError := ac.RemoveOldNonces()

		if removeError == nil {
			t.Fatalf("CheckNonceHash should fail, but checkNonceError is nil")
		}

		errType := ""
		switch removeError.(type) {
		case authCrypto.CryptoKeyError:
			errType = "CryptoKeyError"
		case authCrypto.JWTError:
			errType = "JWTError"
		case dbController.NoResultsError:
			errType = "NoDocumentError"
		case dbController.DBError:
			// It Passed!
			// errType = "DBError"
		case authUtils.NonceError:
			errType = "NonceError"
		default:
			errType = "generic error"
		}

		if len(errType) > 0 {
			t.Fatalf(fmt.Sprint("removeError should be a DBError. it's a ", errType, ". ", removeError.Error()))
		}
	})
	t.Run("RemoveOldNonces succeeds if the return err is nil", func(t *testing.T) {
		tdbc := mocks.MakeBlankTestDbController()
		var passedController dbController.DatabaseController = tdbc
		ac := authServer.InitController(&passedController)

		removeError := ac.RemoveOldNonces()

		if removeError != nil {
			t.Fatalf(fmt.Sprint("CheckNonceHash should not fail, but checkNonceError is not nil. ", removeError.Error()))
		}
	})
}
