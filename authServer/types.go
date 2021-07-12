package authServer

import "time"

const AUTH_DB_NAME = "auth"

const MONGO_DB_URL = "MONGO_DB_URL"
const MONGO_DB_USERNAME = "MONGO_DB_USERNAME"
const MONGO_DB_PASSWORD = "MONGO_DB_PASSWORD"
const RSA_PRIVATE_KEY = "RSA_PRIVATE_KEY"
const RSA_PUBLIC_KEY = "RSA_PUBLIC_KEY"

const FIVE_MINUTES = time.Minute * 5
const TEN_MINUTES = time.Minute * 10

const NONCE_EXPIRATION = -1 * FIVE_MINUTES

const ONE_HOUR = time.Hour
const FOUR_HOURS = time.Hour * 4
const JWT_EXPIRATION = FOUR_HOURS

func GetNonceExpirationTime() int64 {
	// return time.Now().Unix() - NONCE_EXPIRATION
	return time.Now().Add(NONCE_EXPIRATION).Unix()
}

func GetJWTExpirationTime() int64 {
	return time.Now().Add(JWT_EXPIRATION).Unix()
}

type LoginBody struct {
	Username string `form:"username" json:"username" xml:"username"  binding:"required"`
	Password string `form:"password" json:"password" xml:"password" binding:"required"`
	Nonce    string `form:"nonce" json:"nonce" xml:"nonce" binding:"required"`
}

type NonceDocument struct {
	NonceHash     string `bson:"hash"`
	RemoteAddress string `bson:"remoteAddress"`
	Time          int    `bson:"time"`
}

type UserDocument struct {
	Username string `bson:"username"`
	Email    string `bson:"email"`
	Enabled  bool   `bson:"enabled"`
}
