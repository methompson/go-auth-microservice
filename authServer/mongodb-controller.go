package authServer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/gin-gonic/gin"
)

type MongoDbController struct {
	MongoClient *mongo.Client
	dbName      string
}

func (mc MongoDbController) InitDatabase() error {
	userCreationErr := mc.initUserDatabase(mc.dbName)

	// We want to return an error only if it's not the "Collection already exists" error
	// The collection will likely exist most times this app is run. We only want to
	// return an error if there's a larger problem than the collection already existing
	if userCreationErr != nil && !strings.Contains(userCreationErr.Error(), "Collection already exists") {
		return userCreationErr
	}

	nonceCreationErr := mc.initNonceDatabase(mc.dbName)

	if nonceCreationErr != nil && !strings.Contains(nonceCreationErr.Error(), "Collection already exists") {
		return nonceCreationErr
	}

	return nil
}

// Generating and sending a nonce does the following:
// First, it generates a random value of n bits length. This random string is encoded into base64 as a string
// Second, a hash is generated from the bits of data in this string.
// Third, the hash is stored in a database as an available nonce for logging in.
// Fourth, the base64-encoded bit range is sent to the user.
// When a user attempts to log in, this nonce is passed BACK to the server, where it can be decoded, hashed and
// compared to hashes in the Nonce table.
func (mc MongoDbController) GenerateNonce(ctx *gin.Context) (string, error) {
	// Generate a random string and its source bytes
	nonce, bytes := GenerateRandomString(64)
	fmt.Println(nonce)

	hash := hashBytes(bytes)

	// Write the hash to the database
	collection, backCtx, cancel := mc.GetCollection("authNonces")
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

// Returns a JWT on successful user login
func (mc MongoDbController) LogUserIn(body LoginBody, ctx *gin.Context) (string, error) {
	checkHashErr := CheckNonceHash(body, ctx, mc)

	if checkHashErr != nil {
		return "", errors.New("invalid nonce")
	}

	userDoc, userDocErr := mc.getUserByUsername(body.Username, body.Password)

	if userDocErr != nil {
		errorMsg := fmt.Sprint("error retrieving user from database: ", userDocErr)
		return "", errors.New(errorMsg)
	}

	return generateJWT(userDoc)
}

func (mc MongoDbController) GetCollection(collectionName string) (*mongo.Collection, context.Context, context.CancelFunc) {
	// Write the hash to the database
	collection := mc.MongoClient.Database(mc.dbName).Collection(collectionName)
	backCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	return collection, backCtx, cancel
}

func (mc MongoDbController) initUserDatabase(dbName string) error {
	db := mc.MongoClient.Database(dbName)

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

	collection, _, _ := mc.GetCollection("users")
	names, setIndexErr := collection.Indexes().CreateMany(context.TODO(), models, opts)

	if setIndexErr != nil {
		return setIndexErr
	}

	fmt.Printf("created indexes %v\n", names)

	return nil
}

func (mc MongoDbController) initNonceDatabase(dbName string) error {
	db := mc.MongoClient.Database(dbName)

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

	collection, _, _ := mc.GetCollection("authNonces")
	names, setIndexErr := collection.Indexes().CreateMany(context.TODO(), models, opts)

	if setIndexErr != nil {
		return setIndexErr
	}

	fmt.Printf("created indexes %v\n", names)

	return nil
}

func (mc MongoDbController) getUserByUsername(username string, password string) (UserDocument, error) {
	passwordHash := hashString(password)

	fmt.Println(passwordHash)

	collection, backCtx, cancel := mc.GetCollection("users")
	defer cancel()

	var result UserDocument
	mdbErr := collection.FindOne(backCtx, bson.D{
		{Key: "username", Value: username},
		{Key: "passwordHash", Value: passwordHash},
	}).Decode(&result)

	// If no document exists, we'll get an error
	if mdbErr != nil {
		msg := fmt.Sprintln("error getting data from database: ", mdbErr)
		return result, errors.New(msg)
	}

	return result, nil
}

// Once a Nonce has been checked, it should be removed
func (mc MongoDbController) RemoveUsedNonce(hashedNonce string) error {
	collection, backCtx, cancel := mc.GetCollection("authNonces")
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

func (mc MongoDbController) GetNonceFromDb(hashedNonce string, remoteAddress string) (NonceDocument, error) {
	// We only accept nonces that were generated in the past 5 minutes.
	fiveMinutesAgo := time.Now().Unix() - FIVE_MINUTES

	collection, backCtx, cancel := mc.GetCollection("authNonces")
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

func SetupMongoClient() *mongo.Client {
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

func MakeMongoDbController() MongoDbController {
	client := SetupMongoClient()

	return MongoDbController{client, AUTH_DB_NAME}
}
