package authServer

// Use for when there's something wrong with the login process
type LoginError struct{ ErrMsg string }

func (err LoginError) Error() string { return err.ErrMsg }
func NewLoginError(msg string) error { return LoginError{msg} }

// Used for when hashing goes wrong
type HashError struct{ ErrMsg string }

func (err HashError) Error() string { return err.ErrMsg }
func NewHashError(msg string) error { return HashError{msg} }

// Used for when there's an issue with the RSA keys
type CryptoKeyError struct{ ErrMsg string }

func (err CryptoKeyError) Error() string { return err.ErrMsg }
func NewCryptoKeyError(msg string) error { return CryptoKeyError{msg} }

// Used for when there's an issue with reading Nonces
type NonceError struct{ ErrMsg string }

func (err NonceError) Error() string { return err.ErrMsg }
func NewNonceError(msg string) error { return NonceError{msg} }

// Used for when there's an issue with reading Nonces
type EnvironmentVariableError struct{ ErrMsg string }

func (err EnvironmentVariableError) Error() string { return err.ErrMsg }
func NewEnvironmentVariableError(msg string) error { return EnvironmentVariableError{msg} }

// Used for when there's a generic issue reading or writing JWTs
type JWTError struct{ ErrMsg string }

func (err JWTError) Error() string { return err.ErrMsg }
func NewJWTError(msg string) error { return JWTError{msg} }

// Used for when the JWT expires
type ExpiredJWTError struct{ ErrMsg string }

func (err ExpiredJWTError) Error() string { return err.ErrMsg }
func NewExpiredJWTError(msg string) error { return ExpiredJWTError{msg} }
