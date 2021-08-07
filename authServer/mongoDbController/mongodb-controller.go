package mongoDbController

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	dbc "methompson.com/auth-microservice/authServer/dbController"
)

type MongoDbController struct {
	MongoClient *mongo.Client
	dbName      string
}

// InitDatabase runs several commands that create the user and nonce collections.
// It then removes all old Nonces.
func (mdbc MongoDbController) InitDatabase() error {
	userCreationErr := mdbc.initUserCollection(mdbc.dbName)

	// We want to return an error only if it's not the "Collection already exists" error
	// The collection will likely exist most times this app is run. We only want to
	// return an error if there's a larger problem than the collection already existing
	if userCreationErr != nil && !strings.Contains(userCreationErr.Error(), "Collection already exists") {
		return userCreationErr
	}

	nonceCreationErr := mdbc.initNonceDatabase(mdbc.dbName)

	if nonceCreationErr != nil && !strings.Contains(nonceCreationErr.Error(), "Collection already exists") {
		return nonceCreationErr
	}

	initLoggingErr := mdbc.initLoggingDatabase(mdbc.dbName)

	if initLoggingErr != nil && !strings.Contains(nonceCreationErr.Error(), "Collection already exists") {
		return initLoggingErr
	}

	return nil
}

// initUserCollection is a private method that creates the user collection and
// sets the schema for the collection. The function accepts a dbName string
// that represents the name of the database in which the collections are
// created. The schema makes the username, passwordHash, email and enabled
// keys required. Afterward, indexes are created for the collection that make
// username and email unique. The return value is an error in case an errors
// are encountered during initialization.
func (mdbc MongoDbController) initUserCollection(dbName string) error {
	db := mdbc.MongoClient.Database(dbName)

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
		return dbc.NewDBError(createCollectionErr.Error())
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

	collection, _, _ := mdbc.getCollection("users")
	names, setIndexErr := collection.Indexes().CreateMany(context.TODO(), models, opts)

	if setIndexErr != nil {
		return dbc.NewDBError(setIndexErr.Error())
	}

	fmt.Printf("created indexes %v\n", names)

	return nil
}

// initNonceDatabase is a private method that creates the authNonce collection
// and sets the schema for the collection. The function accepts a dbName string
// that represents the name of the database in which the collections are
// created. The schema makes the hash, time and remoteAddress keys required.
// Afterward, indexes are created for the collection making the hash and
// remoteAddresses unique. The return value is an error in case an errors are
// encountered during initialization.
func (mdbc MongoDbController) initNonceDatabase(dbName string) error {
	db := mdbc.MongoClient.Database(dbName)

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
		return dbc.NewDBError(createCollectionErr.Error())
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

	collection, _, _ := mdbc.getCollection("authNonces")
	names, setIndexErr := collection.Indexes().CreateMany(context.TODO(), models, opts)

	if setIndexErr != nil {
		return dbc.NewDBError(setIndexErr.Error())
	}

	fmt.Printf("created indexes %v\n", names)

	return nil
}

func (mdbc MongoDbController) initLoggingDatabase(dbName string) error {
	db := mdbc.MongoClient.Database(dbName)

	jsonSchema := bson.M{
		"bsonType": "object",
		"required": []string{"timeStamp", "type"},
		"properties": bson.M{
			"timeStamp": bson.M{
				"bsonType":    "timestamp",
				"description": "timestamp is required and must be a timestamp",
			},
			"type": bson.M{
				"bsonType":    "string",
				"description": "type is required and must be a string",
			},
		},
	}

	colOpts := options.CreateCollection().SetValidator(bson.M{"$jsonSchema": jsonSchema})
	colOpts.SetCapped(true)
	colOpts.SetSizeInBytes(100000)

	createCollectionErr := db.CreateCollection(context.TODO(), "logging", colOpts)

	if createCollectionErr != nil {
		return dbc.NewDBError(createCollectionErr.Error())
	}

	return nil
}

// getCollection is a convenience function that performs a function used regularly
// throughout the Mongodbc. It accepts a collectionName string for the
// specific collection you want to retrieve, and returns a collection context and
// cancel function.
func (mdbc MongoDbController) getCollection(collectionName string) (*mongo.Collection, context.Context, context.CancelFunc) {
	// Write the hash to the database
	collection := mdbc.MongoClient.Database(mdbc.dbName).Collection(collectionName)
	backCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	return collection, backCtx, cancel
}

// GetUserByUsername attempts to retrieve a user document from the MongoDB database.
// The function accepts a username and password from the user and returns a UserDocument
// struct and an error. The errors returned are either a document error or a database
// error. GetUserByUsername doesn't perform any logic to generate values it uses for
// searching the database.
func (mdbc MongoDbController) GetUserByUsername(username string, passwordHash string) (dbc.UserDocument, error) {
	// passwordHash := hashString(password)

	collection, colCtx, cancel := mdbc.getCollection("users")
	defer cancel()

	var result dbc.UserDocument
	mdbErr := collection.FindOne(colCtx, bson.D{
		{Key: "username", Value: username},
		{Key: "passwordHash", Value: passwordHash},
	}).Decode(&result)

	// If no document exists, we'll get an error
	if mdbErr != nil {
		var err error
		if strings.Contains(mdbErr.Error(), "no documents in result") {
			err = dbc.NewNoResultsError("")
		} else {
			msg := fmt.Sprintln("error getting data from database: ", mdbErr)
			err = dbc.NewDBError(msg)
		}

		return result, err
	}

	return result, nil
}

func (mdbc MongoDbController) AddUser(username string, password string, enabled bool) error {
	return errors.New("Unimplemented")
}
func (mdbc MongoDbController) EditUser(username string, password string, enabled bool) error {
	return errors.New("Unimplemented")
}

// GetNonce attempts to retrieve a nonce value from the authNonces collection from the
// MongoDB database. The function returns a NonceDocument and an error. It only returns
// Nonces that were generated after the expiration time. The expiration time is defined
// in types.go. The errors returned are either a document error (no docuemnts) or a
// database error. GetNonce doesn't perform any logic to calculate the values that are
// used to find the nonce.
func (mdbc MongoDbController) GetNonce(hashedNonce string, remoteAddress string, exp int64) (dbc.NonceDocument, error) {
	collection, backCtx, cancel := mdbc.getCollection("authNonces")
	defer cancel()

	var result dbc.NonceDocument

	// We only accept nonces that were generated after the expiration time
	mdbErr := collection.FindOneAndDelete(backCtx, bson.D{
		{Key: "hash", Value: hashedNonce},
		{Key: "remoteAddress", Value: remoteAddress},
		{Key: "time", Value: bson.M{"$gt": exp}},
	}).Decode(&result)

	if mdbErr != nil {
		var err error

		if strings.Contains(mdbErr.Error(), "no documents in result") {
			err = dbc.NewNonceError("")
		} else {
			msg := fmt.Sprintln("error getting data from database: ", mdbErr.Error())
			err = dbc.NewDBError(msg)
		}

		return result, err
	}

	return result, nil
}

// AddNonce attempts to add a nonce to the authNonces collection. AddNonce takes a
// hashedNonce String, a remoteAddress String and a time int64, indicating when the
// request was made. AddNonce does not perform any logic to calculate the values that are
// eventually saved in the document.
func (mdbc MongoDbController) AddNonce(hashedNonce string, remoteAddress string, time int64) error {
	collection, backCtx, cancel := mdbc.getCollection("authNonces")
	defer cancel()

	// We could use ClientIp, but RemoteAddr contains the ephemeral port, allowing
	// us to target a specific device from an IP address.
	// clientIp := ctx.ClientIP()

	opts := options.Update().SetUpsert(true)
	filter := bson.D{{Key: "remoteAddress", Value: remoteAddress}}
	update := bson.D{{Key: "$set", Value: bson.D{
		{Key: "hash", Value: hashedNonce},
		{Key: "time", Value: time},
		{Key: "remoteAddress", Value: remoteAddress},
	}}}

	_, mdbErr := collection.UpdateOne(backCtx, filter, update, opts)

	if mdbErr != nil {
		return dbc.NewDBError(mdbErr.Error())
	}

	// Return the nonce
	return nil
}

// RemoveOldNonces is a maintenance function that removes all nonce values that
// were added prior to the expiration time passed to the function. exp is the
// expiration time. It represents the amount of seconds since the epoch.
func (mdbc MongoDbController) RemoveOldNonces(exp int64) error {
	collection, backCtx, cancel := mdbc.getCollection("authNonces")
	defer cancel()

	_, mdbErr := collection.DeleteMany(backCtx, bson.D{
		{Key: "time", Value: bson.M{"$lt": exp}},
	})

	if mdbErr != nil {
		return dbc.NewDBError(mdbErr.Error())
	}

	return nil
}

func (mdbc MongoDbController) AddRequestLog(log dbc.RequestLogData) error {
	collection, backCtx, cancel := mdbc.getCollection("logging")
	defer cancel()

	// We could use ClientIp, but RemoteAddr contains the ephemeral port, allowing
	// us to target a specific device from an IP address.
	// clientIp := ctx.ClientIP()

	// filter := bson.D{{Key: "remoteAddress", Value: remoteAddress}}
	insert := bson.D{
		{Key: "timeStamp", Value: primitive.Timestamp{T: uint32(log.TimeStamp.Unix())}},
		{Key: "type", Value: log.Type},
		{Key: "clientIP", Value: log.ClientIP},
		{Key: "method", Value: log.Method},
		{Key: "path", Value: log.Path},
		{Key: "protocol", Value: log.Protocol},
		{Key: "statusCode", Value: log.StatusCode},
		{Key: "latency", Value: log.Latency},
		{Key: "userAgent", Value: log.UserAgent},
		{Key: "errorMessage", Value: log.ErrorMessage},
	}

	_, mdbErr := collection.InsertOne(backCtx, insert)

	if mdbErr != nil {
		print("mdbErr: " + mdbErr.Error() + "\n")
		return dbc.NewDBError(mdbErr.Error())
	}

	// Return the nonce
	return nil
	print("Logging: " + log.PrettyString() + "\n")
	return nil
}

func (mdbc MongoDbController) AddErrorLog(log dbc.ErrorLogData) error {
	collection, backCtx, cancel := mdbc.getCollection("logging")
	defer cancel()

	// We could use ClientIp, but RemoteAddr contains the ephemeral port, allowing
	// us to target a specific device from an IP address.
	// clientIp := ctx.ClientIP()

	// filter := bson.D{{Key: "remoteAddress", Value: remoteAddress}}
	insert := bson.D{
		{Key: "timeStamp", Value: primitive.Timestamp{T: uint32(log.TimeStamp.Unix())}},
		{Key: "type", Value: log.Type},
		{Key: "message", Value: log.Message},
	}

	_, mdbErr := collection.InsertOne(backCtx, insert)

	if mdbErr != nil {
		print("mdbErr: " + mdbErr.Error() + "\n")
		return dbc.NewDBError(mdbErr.Error())
	}

	// Return the nonce
	return nil
	print("Logging: " + log.PrettyString() + "\n")
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
		return client, dbc.NewDBError(err)
	}

	return client, nil
}

func MakeMongoDbController(dbName string) (MongoDbController, error) {
	client, clientErr := setupMongoClient()

	if clientErr != nil {
		return MongoDbController{}, clientErr
	}

	return MongoDbController{client, dbName}, nil
}
