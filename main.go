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
	"github.com/gofrs/uuid"
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

	mongoDbUrl := os.Getenv("MONGO_DB_URL")
	if len(mongoDbUrl) == 0 {
		log.Fatal("MONGO_DB_URL environment variable is required")
	}

	mongoDbUser := os.Getenv("MONGO_DB_USERNAME")
	if len(mongoDbUser) == 0 {
		log.Fatal("MONGO_DB_USERNAME environment variable is required")
	}

	mongoDbPass := os.Getenv("MONGO_DB_PASSWORD")
	if len(mongoDbPass) == 0 {
		log.Fatal("MONGO_DB_PASSWORD environment variable is required")
	}

	hashSecret := os.Getenv("HASH_SECRET")

	if len(hashSecret) == 0 {
		u2, err := uuid.NewV4()
		if err != nil {
			log.Fatalf("failed to generate UUID: %v", err)
		}

		fmt.Println("New UUID: ", u2)
		os.Setenv("HASH_SECRET", u2.String())
	}

	openJwtKeys()
}

func openJwtKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey

	privateKeyBytes, privateKeyBytesErr := os.ReadFile("jwtRS256.key")
	if privateKeyBytesErr != nil {
		return privateKey, publicKey, errors.New("private key does not exist or cannot be read. Run gen-rsa-key.sh to generate a key pair")
	}

	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		fmt.Println("failed to decode private key")
		return privateKey, publicKey, errors.New("failed to decode private key")
	}

	privateKey, privateKeyErr := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if privateKeyErr != nil {
		fmt.Println("failed to parse private key PEM block", privateKeyErr)
		return privateKey, publicKey, errors.New("failed to parse private key PEM block")
	}

	publicKeyBytes, publicKeyBytesErr := os.ReadFile("jwtRS256.key.pub")
	if publicKeyBytesErr != nil {
		return privateKey, publicKey, errors.New("public key does not exist or cannot be read. Run gen-rsa-key.sh to generate a key pair")
	}

	publicKeyBlock, _ := pem.Decode(publicKeyBytes)
	if publicKeyBlock == nil {
		fmt.Println("failed to decode public key")
		return privateKey, publicKey, errors.New("failed to decode public key")
	}

	publicKeyInt, publicKeyIntErr := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if publicKeyIntErr != nil {
		fmt.Println("failed to parse public key PEM block", publicKeyIntErr)
		return privateKey, publicKey, errors.New("failed to parse public key PEM block")
	}

	publicKey, _ = publicKeyInt.(*rsa.PublicKey)

	return privateKey, publicKey, nil
}

func setupServer() *gin.Engine {
	client := setupMongoClient()

	InitDatabase(AUTH_DB_NAME, client)

	r := gin.Default()
	r.GET("/", func(ctx *gin.Context) {
		// ctx.JSON(200, gin.H{
		// 	"message": "Hello!",
		// })
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

		_, loginError := LogUserIn(body, ctx, client)

		if loginError != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": loginError.Error()})
			return
		}

		// if !hashIsGood {
		// 	ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Nonce"})
		// }

		ctx.JSON(200, gin.H{})
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
