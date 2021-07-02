package main

const AUTH_DB_NAME = "auth"

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
