package authServer

type DatabaseController interface {
	InitDatabase() error
	GetUserByUsername(username string, password string) (UserDocument, error)
	GetNonce(hashedNonce string, remoteAddress string) (NonceDocument, error)
	AddNonce(hashedNonce string, remoteAddress string) error
	RemoveOldNonces() error
}
