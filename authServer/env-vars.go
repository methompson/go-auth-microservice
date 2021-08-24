package authServer

import (
	"os"

	"github.com/joho/godotenv"

	ac "methompson.com/auth-microservice/authServer/authCrypto"
	"methompson.com/auth-microservice/authServer/authUtils"
	"methompson.com/auth-microservice/authServer/constants"
)

func LoadEnvVariables() {
	godotenv.Load()
	// if err != nil {
	// 	msg := fmt.Sprint("Error loading .env file: ", err)
	// 	return NewEnvironmentVariableError(msg)
	// }

	// return nil
}

func CheckEnvVariables() error {
	mongoDbUrl := os.Getenv(constants.MONGO_DB_URL)
	if len(mongoDbUrl) == 0 {
		msg := "MONGO_DB_URL environment variable is required"
		return NewEnvironmentVariableError(msg)
	}

	mongoDbUser := os.Getenv(constants.MONGO_DB_USERNAME)
	if len(mongoDbUser) == 0 {
		msg := "MONGO_DB_USERNAME environment variable is required"
		return NewEnvironmentVariableError(msg)
	}

	mongoDbPass := os.Getenv(constants.MONGO_DB_PASSWORD)
	if len(mongoDbPass) == 0 {
		msg := "MONGO_DB_PASSWORD environment variable is required"
		return NewEnvironmentVariableError(msg)
	}

	authUtils.SetHashCost()

	openRSAErr := openAndSetRSAKeys()

	if openRSAErr != nil {
		return openRSAErr
	}

	checkRSAErr := checkRSAKeys()
	if checkRSAErr != nil {
		return checkRSAErr
	}

	return nil
}

func openAndSetRSAKeys() error {
	privateKeyBytes, privateKeyBytesErr := os.ReadFile("./keys/jwtRS256.key")
	if privateKeyBytesErr != nil {
		return ac.NewCryptoKeyError("private key does not exist or cannot be read. Run gen-rsa-key.sh to generate a key pair")
	}

	publicKeyBytes, publicKeyBytesErr := os.ReadFile("./keys/jwtRS256.key.pub")
	if publicKeyBytesErr != nil {
		return ac.NewCryptoKeyError("public key does not exist or cannot be read. Run gen-rsa-key.sh to generate a key pair")
	}

	os.Setenv(constants.RSA_PRIVATE_KEY, string(privateKeyBytes))
	os.Setenv(constants.RSA_PUBLIC_KEY, string(publicKeyBytes))

	return nil
}

func checkRSAKeys() error {
	_, privateKeyError := ac.GetRSAPrivateKey()

	if privateKeyError != nil {
		return privateKeyError
	}

	_, publicKeyError := ac.GetRSAPublicKey()

	if publicKeyError != nil {
		return publicKeyError
	}

	return nil
}
