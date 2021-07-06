package authServer

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/gin-gonic/gin"
)

type MongoDbAuthController struct {
	MongoClient *mongo.Client
	dbName      string
}

func (mc MongoDbAuthController) InitDatabase() error {
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

	removeOldNoncesErr := mc.RemoveOldNonces()

	if removeOldNoncesErr != nil {
		return removeOldNoncesErr
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
func (mc MongoDbAuthController) GenerateNonce(ctx *gin.Context) (string, error) {
	remoteAddress := ctx.Request.RemoteAddr

	removeErr := mc.RemoveNonceByRemoteAddress(remoteAddress)

	if removeErr != nil {
		return "", removeErr
	}

	// Generate a random string and its source bytes
	nonce, bytes := GenerateRandomString(64)

	hash := hashBytes(bytes)

	// Write the hash to the database
	collection, backCtx, cancel := mc.getCollection("authNonces")
	defer cancel()

	// clientIp := ctx.ClientIP()

	_, mdbErr := collection.InsertOne(backCtx, bson.D{
		{Key: "hash", Value: hash},
		{Key: "time", Value: time.Now().Unix()},
		{Key: "remoteAddress", Value: remoteAddress},
	})

	if mdbErr != nil {
		return "", NewDBError(mdbErr.Error())
	}

	// Return the nonce
	return nonce, nil
}

// Returns a JWT on successful user login
func (mc MongoDbAuthController) LogUserIn(body LoginBody, ctx *gin.Context) (string, error) {
	checkHashErr := CheckNonceHash(body, ctx, mc)

	if checkHashErr != nil {
		return "", NewNonceError("invalid nonce")
	}

	userDoc, userDocErr := mc.getUserByUsername(body.Username, body.Password)

	if userDocErr != nil {
		errorMsg := fmt.Sprint("error retrieving user from database: ", userDocErr)
		return "", NewDBError(errorMsg)
	}

	return generateJWT(userDoc)
}

func (mc MongoDbAuthController) getCollection(collectionName string) (*mongo.Collection, context.Context, context.CancelFunc) {
	// Write the hash to the database
	collection := mc.MongoClient.Database(mc.dbName).Collection(collectionName)
	backCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	return collection, backCtx, cancel
}

func (mc MongoDbAuthController) initUserDatabase(dbName string) error {
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
		return NewDBError(createCollectionErr.Error())
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

	collection, _, _ := mc.getCollection("users")
	names, setIndexErr := collection.Indexes().CreateMany(context.TODO(), models, opts)

	if setIndexErr != nil {
		return NewDBError(setIndexErr.Error())
	}

	fmt.Printf("created indexes %v\n", names)

	return nil
}

func (mc MongoDbAuthController) initNonceDatabase(dbName string) error {
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
		return NewDBError(createCollectionErr.Error())
	}

	models := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "hash", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}

	opts := options.CreateIndexes().SetMaxTime(2 * time.Second)

	collection, _, _ := mc.getCollection("authNonces")
	names, setIndexErr := collection.Indexes().CreateMany(context.TODO(), models, opts)

	if setIndexErr != nil {
		return NewDBError(setIndexErr.Error())
	}

	fmt.Printf("created indexes %v\n", names)

	return nil
}

func (mc MongoDbAuthController) getUserByUsername(username string, password string) (UserDocument, error) {
	passwordHash := hashString(password)

	fmt.Println(passwordHash)

	collection, backCtx, cancel := mc.getCollection("users")
	defer cancel()

	var result UserDocument
	mdbErr := collection.FindOne(backCtx, bson.D{
		{Key: "username", Value: username},
		{Key: "passwordHash", Value: passwordHash},
	}).Decode(&result)

	// If no document exists, we'll get an error
	if mdbErr != nil {
		msg := fmt.Sprintln("error getting data from database: ", mdbErr)
		return result, NewDBError(msg)
	}

	return result, nil
}

// Once a Nonce has been checked, it should be removed
func (mc MongoDbAuthController) RemoveUsedNonce(hashedNonce string) error {
	collection, backCtx, cancel := mc.getCollection("authNonces")
	defer cancel()

	_, mdbErr := collection.DeleteMany(backCtx, bson.D{
		{Key: "hash", Value: hashedNonce},
	})

	if mdbErr != nil {
		return NewDBError(mdbErr.Error())
	}

	return nil
}

func (mc MongoDbAuthController) RemoveOldNonces() error {
	collection, backCtx, cancel := mc.getCollection("authNonces")
	defer cancel()

	_, mdbErr := collection.DeleteMany(backCtx, bson.D{
		{Key: "time", Value: bson.M{"$lt": GetExpirationTime()}},
	})

	if mdbErr != nil {
		return NewDBError(mdbErr.Error())
	}

	return nil
}

// Removes all nonces associated with a remote address.
func (mc MongoDbAuthController) RemoveNonceByRemoteAddress(remoteAddress string) error {
	collection, backCtx, cancel := mc.getCollection("authNonces")
	defer cancel()

	_, mdbErr := collection.DeleteMany(backCtx, bson.D{
		{Key: "remoteAddress", Value: remoteAddress},
	})

	if mdbErr != nil {
		return NewDBError(mdbErr.Error())
	}

	return nil
}

// TODO allow only one Nonce per remote address?
func (mc MongoDbAuthController) GetNonceFromDb(hashedNonce string, remoteAddress string) (NonceDocument, error) {

	collection, backCtx, cancel := mc.getCollection("authNonces")
	defer cancel()

	var result NonceDocument

	// We only accept nonces that were generated after the expiration time
	mdbErr := collection.FindOne(backCtx, bson.D{
		{Key: "hash", Value: hashedNonce},
		{Key: "remoteAddress", Value: remoteAddress},
		{Key: "time", Value: bson.M{"$gt": GetExpirationTime()}},
	}).Decode(&result)

	if mdbErr != nil {
		return result, NewDBError(mdbErr.Error())
	}

	return result, nil
}

func SetupMongoClient() (*mongo.Client, error) {
	mongoDbUrl := os.Getenv("MONGO_DB_URL")
	mongoDbUser := os.Getenv("MONGO_DB_USERNAME")
	mongoDbPass := os.Getenv("MONGO_DB_PASSWORD")

	mongoDbFullUrl := fmt.Sprintf("mongodb+srv://%v:%v@%v", mongoDbUser, mongoDbPass, mongoDbUrl)
	clientOptions := options.Client().
		ApplyURI(mongoDbFullUrl)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, mdbErr := mongo.Connect(ctx, clientOptions)

	if mdbErr != nil {
		err := fmt.Sprint("Error connecting: ", mdbErr.Error())
		return client, NewDBError(err)
	}

	return client, nil
}

func MakeMongoDbAuthController() (MongoDbAuthController, error) {
	client, clientErr := SetupMongoClient()

	if clientErr != nil {
		return MongoDbAuthController{}, clientErr
	}

	return MongoDbAuthController{client, AUTH_DB_NAME}, nil
}
