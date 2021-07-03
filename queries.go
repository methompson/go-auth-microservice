package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

const FIVE_MINUTES = 60 * 5

func InitDatabase(dbName string, client *mongo.Client) error {
	userCreationErr := InitUserDatabase(dbName, client)

	// We want to return an error only if it's not the "Collection already exists" error
	// The collection will likely exist most times this app is run. We only want to
	// return an error if there's a larger problem than the collection already existing
	if userCreationErr != nil && !strings.Contains(userCreationErr.Error(), "Collection already exists") {
		return userCreationErr
	}

	nonceCreationErr := InitNonceDatabase(dbName, client)

	if nonceCreationErr != nil && !strings.Contains(nonceCreationErr.Error(), "Collection already exists") {
		return nonceCreationErr
	}

	return nil
}

func InitUserDatabase(dbName string, client *mongo.Client) error {
	db := client.Database(dbName)

	jsonSchema := bson.M{
		"bsonType": "object",
		"required": []string{"username", "passwordHash", "email", "enabled"},
		"properties": bson.M{
			"username": bson.M{
				"bsonType":    "string",
				"description": "username is required and must be a string",
			},
			"passwordHash": bson.M{
				"bsonType":    "string",
				"description": "passwordHash is required and must be a string",
			},
			"email": bson.M{
				"bsonType":    "string",
				"description": "email is required and must be a string",
			},
			"enabled": bson.M{
				"bsonType":    "bool",
				"description": "enabled is required and must be a boolean",
			},
		},
	}

	colOpts := options.CreateCollection().SetValidator(bson.M{"$jsonSchema": jsonSchema})

	createCollectionErr := db.CreateCollection(context.TODO(), "users", colOpts)

	if createCollectionErr != nil {
		return createCollectionErr
	}

	models := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "username", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "email", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}

	opts := options.CreateIndexes().SetMaxTime(2 * time.Second)

	collection, _, _ := GetCollection(dbName, "users", client)
	names, setIndexErr := collection.Indexes().CreateMany(context.TODO(), models, opts)

	if setIndexErr != nil {
		return setIndexErr
	}

	fmt.Printf("created indexes %v\n", names)

	return nil
}

func InitNonceDatabase(dbName string, client *mongo.Client) error {
	db := client.Database(dbName)

	jsonSchema := bson.M{
		"bsonType": "object",
		"required": []string{"hash", "time", "remoteAddress"},
		"properties": bson.M{
			"hash": bson.M{
				"bsonType":    "string",
				"description": "hash is required and must be a string",
			},
			"time": bson.M{
				"bsonType":    "long",
				"description": "time is required and must be a 64-bit integer (aka a long)",
			},
			"remoteAddress": bson.M{
				"bsonType":    "string",
				"description": "remoteAddress is required and must be a string",
			},
		},
	}

	colOpts := options.CreateCollection().SetValidator(bson.M{"$jsonSchema": jsonSchema})

	createCollectionErr := db.CreateCollection(context.TODO(), "authNonces", colOpts)

	if createCollectionErr != nil {
		return createCollectionErr
	}

	models := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "hash", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}

	opts := options.CreateIndexes().SetMaxTime(2 * time.Second)

	collection, _, _ := GetCollection(dbName, "authNonces", client)
	names, setIndexErr := collection.Indexes().CreateMany(context.TODO(), models, opts)

	if setIndexErr != nil {
		return setIndexErr
	}

	fmt.Printf("created indexes %v\n", names)

	return nil
}

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

func hashString(str string) string {
	strBytes := []byte(str)
	return hashBytes(strBytes)
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
func CheckNonceHash(body LoginBody, ctx *gin.Context, client *mongo.Client) error {
	bytes, decodeStringErr := base64.URLEncoding.DecodeString(body.Nonce)
	if decodeStringErr != nil {
		msg := fmt.Sprintln("Invalid Base64 value: ", decodeStringErr)
		fmt.Println(msg)
		return decodeStringErr
	}

	hashedNonce := hashBytes(bytes)

	remoteAddress := ctx.Request.RemoteAddr

	_, nonceDocErr := GetNonceFromDb(hashedNonce, remoteAddress, client)

	if nonceDocErr != nil {
		return nonceDocErr
	}

	// TODO immediately write that the nonce has been used.
	err := removeUsedNonce(hashedNonce, client)

	if err != nil {
		fmt.Println("Error Deleting Nonce: ", err)
	}

	return nil
}

func GetNonceFromDb(hashedNonce string, remoteAddress string, client *mongo.Client) (NonceDocument, error) {
	// We only accept nonces that were generated in the past 5 minutes.
	fiveMinutesAgo := time.Now().Unix() - FIVE_MINUTES

	collection, backCtx, cancel := GetCollection(AUTH_DB_NAME, "authNonces", client)
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

// Once a Nonce has been checked, it should be removed
func removeUsedNonce(hashedNonce string, client *mongo.Client) error {
	collection, backCtx, cancel := GetCollection("auth", "authNonces", client)
	defer cancel()

	_, mdbErr := collection.DeleteMany(backCtx, bson.D{
		{Key: "hash", Value: hashedNonce},
	})

	if mdbErr != nil {
		return mdbErr
	}

	// Return the nonce
	return nil
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

// Returns a JWT
func GetUserByUsername(username string, password string, client *mongo.Client) (string, error) {
	passwordHash := hashString(password)

	fmt.Println(passwordHash)

	collection, backCtx, cancel := GetCollection("auth", "users", client)
	defer cancel()

	var result UserDocument
	mdbErr := collection.FindOne(backCtx, bson.D{
		{Key: "username", Value: username},
		{Key: "passwordHash", Value: passwordHash},
	}).Decode(&result)

	// If no document exists, we'll get an error
	if mdbErr != nil {
		msg := fmt.Sprintln("error getting data from database: ", mdbErr)
		return "", errors.New(msg)
	}

	type CustomClaims struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		jwt.StandardClaims
	}

	claims := CustomClaims{
		result.Username,
		result.Email,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 4).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	privateKey, privateKeyErr := GetRSAPrivateKey()

	if privateKeyErr != nil {
		msg := fmt.Sprintln("error getting private key ", privateKeyErr)
		return "", errors.New(msg)
	}

	signedString, tokenStringErr := token.SignedString(privateKey)

	if tokenStringErr != nil {
		msg := fmt.Sprintln("error making JWT", tokenStringErr)
		return "", errors.New(msg)
	}

	return signedString, nil
}

// Returns a JWT on successful user login
func LogUserIn(body LoginBody, ctx *gin.Context, client *mongo.Client) (string, error) {
	checkHashErr := CheckNonceHash(body, ctx, client)

	if checkHashErr != nil {
		return "", errors.New("invalid nonce")
	}

	return GetUserByUsername(body.Username, body.Password, client)
}
