package dbController

// Used for when there's an issue with a database
type DBError struct{ ErrMsg string }

func (err DBError) Error() string { return err.ErrMsg }
func NewDBError(msg string) error { return DBError{msg} }

type NoResultsError struct{ ErrMsg string }

func (err NoResultsError) Error() string { return err.ErrMsg }
func NewNoResultsError(msg string) error { return NoResultsError{msg} }

// Used for when there's an issue with reading Nonces
type NonceError struct{ ErrMsg string }

func (err NonceError) Error() string { return err.ErrMsg }
func NewNonceError(msg string) error { return NonceError{msg} }
