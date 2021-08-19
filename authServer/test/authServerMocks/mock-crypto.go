package authServerMocks

import (
	"os"

	ac "methompson.com/auth-microservice/authServer/authCrypto"
	"methompson.com/auth-microservice/authServer/constants"
)

func PrepTestRSAKeys() error {
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
