package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/gin-gonic/gin"
)

const FIVE_MINUTES = 60 * 5

// Test function
func QueryUsers(client *mongo.Client) {
	fmt.Println("Querying Users")

	collection := client.Database("auth").Collection("users")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cur, err := collection.Find(ctx, bson.D{})

	if err != nil {
		log.Fatal("Error finding users: ", err)
	}

	defer cur.Close(ctx)

	for cur.Next(ctx) {
		var result bson.D
		err := cur.Decode(&result)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("result")
		// do something with result....
	}

	if err := cur.Err(); err != nil {
		log.Fatal(err)
	}
}

func GetCollection(dbName string, collectionName string, client *mongo.Client) (*mongo.Collection, context.Context, context.CancelFunc) {
	// Write the hash to the database
	collection := client.Database(dbName).Collection(collectionName)
	backCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	return collection, backCtx, cancel
}

// Generating and sending a nonce does the following:
// First, it generates a random value of n bits length. This random string is encoded into base64 as a string
// Second, a hash is generated from the bits of data in this string.
// Third, the hash is stored in a database as an available nonce for logging in.
// Fourth, the base64-encoded bit range is sent to the user.
// When a user attempts to log in, this nonce is passed BACK to the server, where it can be decoded, hashed and
// compared to hashes in the Nonce table.
func GenerateNonce(ctx *gin.Context, client *mongo.Client) (string, error) {
	// Generate a random string and its source bytes
	nonce, bytes := GenerateRandomString(64)
	fmt.Println(nonce)

	hash := hashBytes(bytes)

	// Write the hash to the database
	collection, backCtx, cancel := GetCollection("auth", "authNonces", client)
	defer cancel()

	_, mdbErr := collection.InsertOne(backCtx, bson.D{
		{Key: "hash", Value: hash},
		{Key: "time", Value: time.Now().Unix()},
		{Key: "remoteAddress", Value: ctx.Request.RemoteAddr},
	})

	if mdbErr != nil {
		return "", mdbErr
	}

	// Return the nonce
	return nonce, nil
}

// Takes an array of bytes and calculates the sha3-512 hash of the bytes array
func hashBytes(bytes []byte) string {
	// Hash the value using sha3-512
	hasher := crypto.SHA3_512.New()
	hasher.Write(bytes)
	sum := hasher.Sum(nil)
	sha3 := fmt.Sprintf("%x", sum)

	return sha3
}

// This function will accept the login body data, the request context and the mongodb
// client. It calculates the hash from the base 64 encoded data, then looks for the
// hash in the authNonces Document collection.
func CheckNonceHash(body LoginBody, ctx *gin.Context, client *mongo.Client) (bool, error) {
	bytes, decodeStringErr := base64.URLEncoding.DecodeString(body.Nonce)
	if decodeStringErr != nil {
		msg := fmt.Sprintln("Invalid Base64 value: ", decodeStringErr)
		fmt.Println(msg)
		return false, decodeStringErr
	}

	hashedNonce := hashBytes(bytes)

	remoteAddress := ctx.Request.RemoteAddr

	_, nonceDocErr := GetNonceFromDb(hashedNonce, remoteAddress, client)

	if nonceDocErr != nil {
		return false, nonceDocErr
	}

	return true, nil
}

func GetNonceFromDb(hashedNonce string, remoteAddress string, client *mongo.Client) (NonceDocument, error) {
	// We only accept nonces that were generated in the past 5 minutes.
	fiveMinutesAgo := time.Now().Unix() - FIVE_MINUTES

	collection, backCtx, cancel := GetCollection("auth", "authNonces", client)
	defer cancel()

	var result NonceDocument

	mdbErr := collection.FindOne(backCtx, bson.D{
		{Key: "hash", Value: hashedNonce},
		{Key: "remoteAddress", Value: remoteAddress},
		{Key: "time", Value: bson.M{"$gt": fiveMinutesAgo}},
	}).Decode(&result)

	if mdbErr != nil {
		return result, mdbErr
	}

	return result, nil
}

// Generate a random string of n bits length. 64 bits is a good starting point for
// generating a somewhat secure value. We return both a base 64 encoded string and
// the actual bytes. The string is, eventually returned to the client and the bytes
// are used for hashing the value and saving to the database. We could just return
// the base 64 encoded string and use a base 64 decoder, but returning the bytes
// representation should save a few ops
func GenerateRandomString(bits int) (string, []byte) {
	byt := make([]byte, bits)
	_, randReadErr := rand.Read(byt)

	if randReadErr != nil {
		errLog := fmt.Sprintln("Random Generator Error ", randReadErr)
		fmt.Println(errLog)
		log.Fatal(errLog)
	}

	b64 := base64.URLEncoding.EncodeToString(byt)

	return b64, byt
}

func GetUserByUsername(username string, client *mongo.Client) {
	collection, backCtx, cancel := GetCollection("auth", "users", client)
	defer cancel()

	var result bson.M
	mdbErr := collection.FindOne(backCtx, bson.D{}).Decode(&result)

	if mdbErr != nil {
		fmt.Println("There was an error")
	}
}
