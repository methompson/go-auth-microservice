package authServerTest

import (
	"os"

	"methompson.com/auth-microservice/authServer"
)

func PrepTestRSAKeys() error {
	privateKeyBytes, privateKeyBytesErr := os.ReadFile("./keys/jwtRS256.key")
	if privateKeyBytesErr != nil {
		return authServer.NewCryptoKeyError("private key does not exist or cannot be read. Run gen-rsa-key.sh to generate a key pair")
	}

	publicKeyBytes, publicKeyBytesErr := os.ReadFile("./keys/jwtRS256.key.pub")
	if publicKeyBytesErr != nil {
		return authServer.NewCryptoKeyError("public key does not exist or cannot be read. Run gen-rsa-key.sh to generate a key pair")
	}

	os.Setenv(authServer.RSA_PRIVATE_KEY, string(privateKeyBytes))
	os.Setenv(authServer.RSA_PUBLIC_KEY, string(publicKeyBytes))

	return nil
}
