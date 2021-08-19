package authServer

// Use for when there's something wrong with the login process
type LoginError struct{ ErrMsg string }

func (err LoginError) Error() string { return err.ErrMsg }
func NewLoginError(msg string) error { return LoginError{msg} }

// Use for when a user is not authorized to perform an action.
type UnauthorizedError struct{ ErrMsg string }

func (err UnauthorizedError) Error() string { return err.ErrMsg }
func NewUnauthorizedError(msg string) error { return UnauthorizedError{msg} }

// Used for when hashing goes wrong
type HashError struct{ ErrMsg string }

func (err HashError) Error() string { return err.ErrMsg }
func NewHashError(msg string) error { return HashError{msg} }

// Used for when there's an issue with reading Nonces
type EnvironmentVariableError struct{ ErrMsg string }

func (err EnvironmentVariableError) Error() string { return err.ErrMsg }
func NewEnvironmentVariableError(msg string) error { return EnvironmentVariableError{msg} }
