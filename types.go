package main

const AUTH_DB_NAME = "auth"

const MONGO_DB_URL = "MONGO_DB_URL"
const MONGO_DB_USERNAME = "MONGO_DB_USERNAME"
const MONGO_DB_PASSWORD = "MONGO_DB_PASSWORD"
const RSA_PRIVATE_KEY = "RSA_PRIVATE_KEY"
const RSA_PUBLIC_KEY = "RSA_PUBLIC_KEY"

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
