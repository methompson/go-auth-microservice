package authServer

import "time"

const AUTH_DB_NAME = "auth"

const MONGO_DB_URL = "MONGO_DB_URL"
const MONGO_DB_USERNAME = "MONGO_DB_USERNAME"
const MONGO_DB_PASSWORD = "MONGO_DB_PASSWORD"
const RSA_PRIVATE_KEY = "RSA_PRIVATE_KEY"
const RSA_PUBLIC_KEY = "RSA_PUBLIC_KEY"

const FILE_LOGGING = "FILE_LOGGING"
const FILE_LOGGING_PATH = "FILE_LOGGING_PATH"
const DB_LOGGING = "DB_LOGGING"
const CONSOLE_LOGGING = "CONSOLE_LOGGING"

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
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Nonce    string `json:"nonce" binding:"required"`
}

type AddUserBody struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
	Admin    bool   `json:"admin"`
	Nonce    string `json:"nonce" binding:"required"`
}

type AdminHeader struct {
	Token string `header:"authorization" binding:"required"`
}
