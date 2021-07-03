package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	loadAndCheckEnvVariables()

	r := setupServer()
	r.Run()
}

func loadAndCheckEnvVariables() {
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
		return errors.New("private key does not exist or cannot be read. Run gen-rsa-key.sh to generate a key pair")
	}

	publicKeyBytes, publicKeyBytesErr := os.ReadFile("./keys/jwtRS256.key.pub")
	if publicKeyBytesErr != nil {
		return errors.New("public key does not exist or cannot be read. Run gen-rsa-key.sh to generate a key pair")
	}

	os.Setenv(RSA_PRIVATE_KEY, string(privateKeyBytes))
	os.Setenv(RSA_PUBLIC_KEY, string(publicKeyBytes))

	return nil
}

func GetRSAPrivateKey() (*rsa.PrivateKey, error) {
	var privateKey *rsa.PrivateKey

	privateKeyStr := os.Getenv(RSA_PRIVATE_KEY)

	privateKeyBytes := []byte(privateKeyStr)

	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		fmt.Println("failed to decode private key")
		return privateKey, errors.New("failed to decode private key")
	}

	privateKey, privateKeyErr := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if privateKeyErr != nil {
		fmt.Println("failed to parse private key PEM block", privateKeyErr)
		return privateKey, errors.New("failed to parse private key PEM block")
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
		return publicKey, errors.New("failed to decode public key")
	}

	publicKeyInt, publicKeyIntErr := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if publicKeyIntErr != nil {
		fmt.Println("failed to parse public key PEM block", publicKeyIntErr)
		return publicKey, errors.New("failed to parse public key PEM block")
	}

	publicKey, _ = publicKeyInt.(*rsa.PublicKey)

	return publicKey, nil
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

func setupServer() *gin.Engine {
	client := setupMongoClient()

	initDbErr := InitDatabase(AUTH_DB_NAME, client)

	if initDbErr != nil {
		log.Fatal("Error Initializing Database", initDbErr)
	}

	r := gin.Default()
	r.GET("/", func(ctx *gin.Context) {
		ctx.Data(200, "text/html; charset=utf-8", make([]byte, 0))
	})

	r.GET("/nonce", func(ctx *gin.Context) {
		nonce, err := GenerateNonce(ctx, client)

		if err != nil {
			ctx.JSON(500, gin.H{})
			return
		}

		ctx.JSON(200, gin.H{
			"nonce": nonce,
		})
	})

	r.POST("/login", func(ctx *gin.Context) {
		var body LoginBody

		if bindJsonErr := ctx.ShouldBindJSON(&body); bindJsonErr != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": bindJsonErr.Error()})
			return
		}

		token, loginError := LogUserIn(body, ctx, client)

		if loginError != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": loginError.Error()})
			return
		}

		ctx.JSON(200, gin.H{
			"token": token,
		})
	})

	r.POST("/verify-token", func(ctx *gin.Context) {})

	r.GET("/public-key", func(ctx *gin.Context) {
		ctx.String(200, os.Getenv(RSA_PUBLIC_KEY))
	})

	return r
}

func setupMongoClient() *mongo.Client {
	mongoDbUrl := os.Getenv("MONGO_DB_URL")
	mongoDbUser := os.Getenv("MONGO_DB_USERNAME")
	mongoDbPass := os.Getenv("MONGO_DB_PASSWORD")

	mongoDbFullUrl := fmt.Sprintf("mongodb+srv://%v:%v@%v", mongoDbUser, mongoDbPass, mongoDbUrl)
	clientOptions := options.Client().
		ApplyURI(mongoDbFullUrl)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)

	if err != nil {
		log.Fatal("Error connecting ", err)
	}

	return client
}
