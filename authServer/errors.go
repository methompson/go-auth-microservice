package authServer

type HashError struct {
	ErrMsg string
}

func (err HashError) Error() string {
	return err.ErrMsg
}

func NewHashError(msg string) error {
	return HashError{msg}
}

type CryptoKeyError struct {
	ErrMsg string
}

func (err CryptoKeyError) Error() string {
	return err.ErrMsg
}

func NewCryptoKeyError(msg string) error {
	return CryptoKeyError{msg}
}

type JWTError struct{ ErrMsg string }

func (err JWTError) Error() string { return err.ErrMsg }
func NewJWTError(msg string) error { return JWTError{msg} }

type DBError struct {
	ErrMsg string
}

func (err DBError) Error() string {
	return err.ErrMsg
}

func NewDBError(msg string) error {
	return DBError{msg}
}

type NonceError struct {
	ErrMsg string
}

func (err NonceError) Error() string {
	return err.ErrMsg
}

func NewNonceError(msg string) error {
	return NonceError{msg}
}
