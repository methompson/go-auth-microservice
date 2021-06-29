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
)

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

func WriteUsers(client *mongo.Client) {}

func InitDb(client *mongo.Client) {}

// Generating and sending a nonce does the following:
// First, it generates a random value of n bits length. This random string is encoded into base64 as a string
// Second, a hash is generated from the bits of data in this string.
// Third, the hash is stored in a database as an available nonce for logging in.
// Fourth, the base64-encoded bit range is sent to the user.
// When a user attempts to log in, this nonce is passed BACK to the server, where it can be decoded, hashed and
// compared to all hashes in the Nonce table
func GenerateNonce(client *mongo.Client) (string, error) {
	// Generate a random string and its source bytes
	nonce, bytes := GenerateRandomString(64)
	fmt.Println(nonce)

	// Hash the value using sha3-512
	hasher := crypto.SHA3_512.New()
	hasher.Write(bytes)
	sum := hasher.Sum(nil)
	sha3 := fmt.Sprintf("%x", sum)

	// Write the hash to the database
	collection := client.Database("auth").Collection("authNonces")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, bson.D{{"name", "hash"}, {"value", sha3}})
	if err != nil {
		return "", err
	}

	fmt.Println(sha3)

	// Return the nonce
	return nonce, nil
}

func CheckNonceHash(b64 string) bool {
	hasher := crypto.SHA3_512.New()
	bytes, err2 := base64.URLEncoding.DecodeString(b64)
	if err2 != nil {
		fmt.Println("Invalid Base64 value: ", err2)
		return false
	}

	hasher.Write(bytes)
	sum := hasher.Sum(nil)
	sha3 := fmt.Sprintf("%x", sum)
	fmt.Println(sha3)

	return true
}

// Generate a random string of n bits length. 64 bits is a good starting point for
// generating a somewhat secure value.
func GenerateRandomString(bits int) (string, []byte) {
	by := make([]byte, bits)
	_, err := rand.Read(by)

	if err != nil {
		errLog := fmt.Sprintln("Random Generator Error ", err)
		fmt.Println(errLog)
		log.Fatal(errLog)
	}

	b64 := base64.URLEncoding.EncodeToString(by)

	return b64, by
}

func CheckNonce(nonce string) {}
