package authUtilsTest

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"methompson.com/auth-microservice/authServer/authUtils"
	"methompson.com/auth-microservice/authServer/constants"
)

const testStringHash = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14"
const emptyStringHash = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"

func Test_HashBytes(t *testing.T) {
	t.Run("HashBytes will return the proper sha3-512 hashed string for a specific input", func(t *testing.T) {
		var hashedString string

		hashedString = authUtils.HashBytes([]byte(""))
		if hashedString != emptyStringHash {
			t.Fatalf("hashedString does not match the empty string reference hash")
		}

		hashedString = authUtils.HashBytes([]byte("test"))
		if hashedString != testStringHash {
			t.Fatalf("hashedString does not match the empty string reference hash")
		}
	})
}

func Test_HashString(t *testing.T) {
	t.Run("HashString will return the proper sha3-512 hashed string for a specific input", func(t *testing.T) {
		var hashedString string

		hashedString = authUtils.HashString("")
		if hashedString != emptyStringHash {
			t.Fatalf("hashedString does not match the empty string reference hash")
		}

		hashedString = authUtils.HashString("test")
		if hashedString != testStringHash {
			t.Fatalf("hashedString does not match the empty string reference hash")
		}
	})
}

func resetEnvVariables() {
	os.Setenv(constants.HASH_COST, "4")

	authUtils.SetHashCost()
}

func Test_HashPassword(t *testing.T) {
	t.Run("HashPassword will return a value that can be checked and confirmed working", func(t *testing.T) {
		resetEnvVariables()

		pass := "test"

		cryptedPass, cryptedPassErr := authUtils.HashPassword(pass)

		if cryptedPassErr != nil {
			t.Fatalf("cruptedPassErr should be nil: " + cryptedPassErr.Error())
		}

		compareErr := bcrypt.CompareHashAndPassword([]byte(cryptedPass), []byte(pass))

		if compareErr != nil {
			t.Fatalf("compareErr should be nil: " + compareErr.Error())
		}
	})
}

func Test_CheckPasswordHash(t *testing.T) {
	// This was calculated elsewhere using a reference implementation of bcrypt for "test"
	hash := "$2a$04$xFAKEZ48kNiQREZhOUK9VevNIpk87r2FcI6xjX/J33zSgbe/8pfX."
	t.Run("CheckPasswordHash will return true if the password provided matches the hash", func(t *testing.T) {
		result := authUtils.CheckPasswordHash("test", hash)

		if !result {
			t.Fatalf("result should be true")
		}
	})

	t.Run("CheckPasswordHash will return false if the password provided does not match the hash", func(t *testing.T) {
		result := authUtils.CheckPasswordHash("test1", hash)

		if result {
			t.Fatalf("result should be false")
		}
	})
}
