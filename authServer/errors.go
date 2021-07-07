package authServer

// Used for when hashing goes wrong
type HashError struct{ ErrMsg string }

func (err HashError) Error() string { return err.ErrMsg }
func NewHashError(msg string) error { return HashError{msg} }

// Used for when there's an issue with the RSA keys
type CryptoKeyError struct{ ErrMsg string }

func (err CryptoKeyError) Error() string { return err.ErrMsg }
func NewCryptoKeyError(msg string) error { return CryptoKeyError{msg} }

// Used for when there's an issue reading or writing JWTs
type JWTError struct{ ErrMsg string }

func (err JWTError) Error() string { return err.ErrMsg }
func NewJWTError(msg string) error { return JWTError{msg} }

// Used for when there's an issue with a database
type DBError struct{ ErrMsg string }

func (err DBError) Error() string { return err.ErrMsg }
func NewDBError(msg string) error { return DBError{msg} }

type NoDocError struct{ ErrMsg string }

func (err NoDocError) Error() string { return err.ErrMsg }
func NewNoDocError(msg string) error { return NoDocError{msg} }

// Used for when there's an issue with reading Nonces
type NonceError struct{ ErrMsg string }

func (err NonceError) Error() string { return err.ErrMsg }
func NewNonceError(msg string) error { return NonceError{msg} }
