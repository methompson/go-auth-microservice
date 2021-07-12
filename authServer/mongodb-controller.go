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
)

type MongoDbController struct {
	MongoClient *mongo.Client
	dbName      string
}

func (mdac MongoDbController) InitDatabase() error {
	userCreationErr := mdac.initUserDatabase(mdac.dbName)

	// We want to return an error only if it's not the "Collection already exists" error
	// The collection will likely exist most times this app is run. We only want to
	// return an error if there's a larger problem than the collection already existing
	if userCreationErr != nil && !strings.Contains(userCreationErr.Error(), "Collection already exists") {
		return userCreationErr
	}

	nonceCreationErr := mdac.initNonceDatabase(mdac.dbName)

	if nonceCreationErr != nil && !strings.Contains(nonceCreationErr.Error(), "Collection already exists") {
		return nonceCreationErr
	}

	removeOldNoncesErr := mdac.RemoveOldNonces()

	if removeOldNoncesErr != nil {
		return removeOldNoncesErr
	}

	return nil
}

func (mdac MongoDbController) initUserDatabase(dbName string) error {
	db := mdac.MongoClient.Database(dbName)

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

	collection, _, _ := mdac.getCollection("users")
	names, setIndexErr := collection.Indexes().CreateMany(context.TODO(), models, opts)

	if setIndexErr != nil {
		return NewDBError(setIndexErr.Error())
	}

	fmt.Printf("created indexes %v\n", names)

	return nil
}

func (mdac MongoDbController) initNonceDatabase(dbName string) error {
	db := mdac.MongoClient.Database(dbName)

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
		{
			Keys:    bson.D{{Key: "remoteAddress", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}

	opts := options.CreateIndexes().SetMaxTime(2 * time.Second)

	collection, _, _ := mdac.getCollection("authNonces")
	names, setIndexErr := collection.Indexes().CreateMany(context.TODO(), models, opts)

	if setIndexErr != nil {
		return NewDBError(setIndexErr.Error())
	}

	fmt.Printf("created indexes %v\n", names)

	return nil
}

func (mdac MongoDbController) getCollection(collectionName string) (*mongo.Collection, context.Context, context.CancelFunc) {
	// Write the hash to the database
	collection := mdac.MongoClient.Database(mdac.dbName).Collection(collectionName)
	backCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	return collection, backCtx, cancel
}

func (mdac MongoDbController) GetUserByUsername(username string, password string) (UserDocument, error) {
	passwordHash := hashString(password)

	fmt.Println(passwordHash)

	collection, backCtx, cancel := mdac.getCollection("users")
	defer cancel()

	var result UserDocument
	mdbErr := collection.FindOne(backCtx, bson.D{
		{Key: "username", Value: username},
		{Key: "passwordHash", Value: passwordHash},
	}).Decode(&result)

	// If no document exists, we'll get an error
	if mdbErr != nil {
		var err error
		if strings.Contains(mdbErr.Error(), "no documents in result") {
			err = NewNoDocError("")
		} else {
			msg := fmt.Sprintln("error getting data from database: ", mdbErr)
			err = NewDBError(msg)
		}

		return result, err
	}

	return result, nil
}

func (mdac MongoDbController) GetNonce(hashedNonce string, remoteAddress string) (NonceDocument, error) {
	collection, backCtx, cancel := mdac.getCollection("authNonces")
	defer cancel()

	var result NonceDocument

	// We only accept nonces that were generated after the expiration time
	mdbErr := collection.FindOneAndDelete(backCtx, bson.D{
		{Key: "hash", Value: hashedNonce},
		{Key: "remoteAddress", Value: remoteAddress},
		{Key: "time", Value: bson.M{"$gt": GetNonceExpirationTime()}},
	}).Decode(&result)

	if mdbErr != nil {
		var err error

		if strings.Contains(mdbErr.Error(), "no documents in result") {
			err = NewNonceError("")
		} else {
			msg := fmt.Sprintln("error getting data from database: ", mdbErr.Error())
			err = NewDBError(msg)
		}

		return result, err
	}

	return result, nil
}

func (mdac MongoDbController) AddNonce(hashedNonce string, remoteAddress string) error {
	collection, backCtx, cancel := mdac.getCollection("authNonces")
	defer cancel()

	// We could use ClientIp, but RemoteAddr contains the ephemeral port, allowing
	// us to target a specific device from an IP address.
	// clientIp := ctx.ClientIP()

	opts := options.Update().SetUpsert(true)
	filter := bson.D{{Key: "remoteAddress", Value: remoteAddress}}
	update := bson.D{{Key: "$set", Value: bson.D{
		{Key: "hash", Value: hashedNonce},
		{Key: "time", Value: time.Now().Unix()},
		{Key: "remoteAddress", Value: remoteAddress},
	}}}

	_, mdbErr := collection.UpdateOne(backCtx, filter, update, opts)

	if mdbErr != nil {
		return NewDBError(mdbErr.Error())
	}

	// Return the nonce
	return nil
}

func (mdac MongoDbController) RemoveOldNonces() error {
	collection, backCtx, cancel := mdac.getCollection("authNonces")
	defer cancel()

	_, mdbErr := collection.DeleteMany(backCtx, bson.D{
		{Key: "time", Value: bson.M{"$lt": GetNonceExpirationTime()}},
	})

	if mdbErr != nil {
		return NewDBError(mdbErr.Error())
	}

	return nil
}

func setupMongoClient() (*mongo.Client, error) {
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

func MakeMongoDbController() (MongoDbController, error) {
	client, clientErr := setupMongoClient()

	if clientErr != nil {
		return MongoDbController{}, clientErr
	}

	return MongoDbController{client, AUTH_DB_NAME}, nil
}
