package dbController

import au "methompson.com/auth-microservice/authServer/authUtils"

type DatabaseController interface {
	InitDatabase() error

	GetUserByUsername(username string, password string) (UserDocument, error)
	AddUser(userDoc UserDocument, passwordHash string) error
	EditUser(userDoc UserDocument, passwordHash string) error

	GetNonce(hashedNonce string, remoteAddress string, exp int64) (NonceDocument, error)
	AddNonce(hashedNonce string, remoteAddress string, time int64) error
	RemoveOldNonces(exp int64) error

	AddRequestLog(log *au.RequestLogData) error
	AddInfoLog(log *au.InfoLogData) error
}
