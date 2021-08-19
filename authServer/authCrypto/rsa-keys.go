package authCrypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"

	"methompson.com/auth-microservice/authServer/constants"
)

// Used for when there's an issue with the RSA keys
type CryptoKeyError struct{ ErrMsg string }

func (err CryptoKeyError) Error() string { return err.ErrMsg }
func NewCryptoKeyError(msg string) error { return CryptoKeyError{msg} }

func GetRSAPrivateKey() (*rsa.PrivateKey, error) {
	var privateKey *rsa.PrivateKey

	privateKeyStr := os.Getenv(constants.RSA_PRIVATE_KEY)

	privateKeyBytes := []byte(privateKeyStr)

	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		// fmt.Println("failed to decode private key")
		return privateKey, NewCryptoKeyError("failed to decode private key")
	}

	privateKey, privateKeyErr := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if privateKeyErr != nil {
		// fmt.Println("failed to parse private key PEM block", privateKeyErr)
		return privateKey, NewCryptoKeyError("failed to parse private key PEM block")
	}

	return privateKey, nil
}

func GetRSAPublicKey() (*rsa.PublicKey, error) {
	var publicKey *rsa.PublicKey

	publicKeyStr := os.Getenv(constants.RSA_PUBLIC_KEY)

	publicKeyBytes := []byte(publicKeyStr)

	publicKeyBlock, _ := pem.Decode(publicKeyBytes)
	if publicKeyBlock == nil {
		// fmt.Println("failed to decode public key")
		return publicKey, NewCryptoKeyError("failed to decode public key")
	}

	publicKeyInt, publicKeyIntErr := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if publicKeyIntErr != nil {
		// fmt.Println("failed to parse public key PEM block", publicKeyIntErr)
		return publicKey, NewCryptoKeyError("failed to parse public key PEM block")
	}

	publicKey, _ = publicKeyInt.(*rsa.PublicKey)

	return publicKey, nil
}
