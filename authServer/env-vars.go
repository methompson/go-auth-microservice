package authServer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func LoadAndCheckEnvVariables() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file: ", err)
	}

	mongoDbUrl := os.Getenv(MONGO_DB_URL)
	if len(mongoDbUrl) == 0 {
		log.Fatal("MONGO_DB_URL environment variable is required")
	}

	mongoDbUser := os.Getenv(MONGO_DB_USERNAME)
	if len(mongoDbUser) == 0 {
		log.Fatal("MONGO_DB_USERNAME environment variable is required")
	}

	mongoDbPass := os.Getenv(MONGO_DB_PASSWORD)
	if len(mongoDbPass) == 0 {
		log.Fatal("MONGO_DB_PASSWORD environment variable is required")
	}

	openRSAErr := openAndSetRSAKeys()

	if openRSAErr != nil {
		msg := fmt.Sprintln("error opening RSA keys.", openRSAErr)
		log.Fatal(msg)
	}

	checkRSAErr := checkRSAKeys()
	if checkRSAErr != nil {
		msg := fmt.Sprintln("cannot read RSA keys", checkRSAErr)
		log.Fatal(msg)
	}
}

func openAndSetRSAKeys() error {
	privateKeyBytes, privateKeyBytesErr := os.ReadFile("./keys/jwtRS256.key")
	if privateKeyBytesErr != nil {
		return NewCryptoKeyError("private key does not exist or cannot be read. Run gen-rsa-key.sh to generate a key pair")
	}

	publicKeyBytes, publicKeyBytesErr := os.ReadFile("./keys/jwtRS256.key.pub")
	if publicKeyBytesErr != nil {
		return NewCryptoKeyError("public key does not exist or cannot be read. Run gen-rsa-key.sh to generate a key pair")
	}

	os.Setenv(RSA_PRIVATE_KEY, string(privateKeyBytes))
	os.Setenv(RSA_PUBLIC_KEY, string(publicKeyBytes))

	return nil
}

func checkRSAKeys() error {
	_, privateKeyError := GetRSAPrivateKey()

	if privateKeyError != nil {
		return privateKeyError
	}

	_, publicKeyError := GetRSAPublicKey()

	if publicKeyError != nil {
		return publicKeyError
	}

	return nil
}

func GetRSAPrivateKey() (*rsa.PrivateKey, error) {
	var privateKey *rsa.PrivateKey

	privateKeyStr := os.Getenv(RSA_PRIVATE_KEY)

	privateKeyBytes := []byte(privateKeyStr)

	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		fmt.Println("failed to decode private key")
		return privateKey, NewCryptoKeyError("failed to decode private key")
	}

	privateKey, privateKeyErr := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if privateKeyErr != nil {
		fmt.Println("failed to parse private key PEM block", privateKeyErr)
		return privateKey, NewCryptoKeyError("failed to parse private key PEM block")
	}

	return privateKey, nil
}

func GetRSAPublicKey() (*rsa.PublicKey, error) {
	var publicKey *rsa.PublicKey

	publicKeyStr := os.Getenv(RSA_PUBLIC_KEY)

	publicKeyBytes := []byte(publicKeyStr)

	publicKeyBlock, _ := pem.Decode(publicKeyBytes)
	if publicKeyBlock == nil {
		fmt.Println("failed to decode public key")
		return publicKey, NewCryptoKeyError("failed to decode public key")
	}

	publicKeyInt, publicKeyIntErr := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if publicKeyIntErr != nil {
		fmt.Println("failed to parse public key PEM block", publicKeyIntErr)
		return publicKey, NewCryptoKeyError("failed to parse public key PEM block")
	}

	publicKey, _ = publicKeyInt.(*rsa.PublicKey)

	return publicKey, nil
}
