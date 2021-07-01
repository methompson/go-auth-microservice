package main

import (
	"context"
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
	}
}

func setupServer() *gin.Engine {
	client := setupMongoClient()

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

		hashIsGood, hashIsGoodErr := CheckNonceHash(body, ctx, client)

		if hashIsGoodErr != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": hashIsGoodErr.Error()})
			return
		}

		if !hashIsGood {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Nonce"})
		}

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
