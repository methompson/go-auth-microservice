package dbController

type DatabaseController interface {
	InitDatabase() error

	GetUserByUsername(username string, password string) (UserDocument, error)
	AddUser(username string, password string, enabled bool) error
	EditUser(username string, password string, enabled bool) error

	GetNonce(hashedNonce string, remoteAddress string, exp int64) (NonceDocument, error)
	AddNonce(hashedNonce string, remoteAddress string, time int64) error
	RemoveOldNonces(exp int64) error

	AddRequestLog(log RequestLogData) error
	AddErrorLog(log ErrorLogData) error
}
