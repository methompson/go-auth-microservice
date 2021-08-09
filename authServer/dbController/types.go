package dbController

type NonceDocument struct {
	NonceHash     string `bson:"hash"`
	RemoteAddress string `bson:"remoteAddress"`
	Time          int    `bson:"time"`
}

type UserDocument struct {
	Username string `bson:"username"`
	Email    string `bson:"email"`
	Enabled  bool   `bson:"enabled"`
	Admin    bool   `bson:"admin"`
}
