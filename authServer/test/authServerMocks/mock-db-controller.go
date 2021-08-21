package authServerMocks

import (
	"errors"

	au "methompson.com/auth-microservice/authServer/authUtils"
	dbc "methompson.com/auth-microservice/authServer/dbController"
)

type TestDbController struct {
	initDbErr          error
	userDoc            dbc.FullUserDocument
	userDocErr         error
	nonceDoc           dbc.NonceDocument
	nonceDocErr        error
	addNonceErr        error
	removeOldNoncesErr error
	hashedPass         string
	editUserErr        error
}

func MakeBlankTestDbController() TestDbController {
	return TestDbController{
		initDbErr:          nil,
		userDoc:            dbc.FullUserDocument{},
		userDocErr:         nil,
		nonceDoc:           dbc.NonceDocument{},
		nonceDocErr:        nil,
		addNonceErr:        nil,
		removeOldNoncesErr: nil,
		hashedPass:         "",
		editUserErr:        nil,
	}
}

func (tdc TestDbController) InitDatabase() error {
	return tdc.initDbErr
}

func (tdc TestDbController) GetUserByUsername(username string) (dbc.FullUserDocument, error) {
	return tdc.userDoc, tdc.userDocErr
}

func (tdc TestDbController) GetUserById(id string) (dbc.FullUserDocument, error) {
	return tdc.userDoc, tdc.userDocErr
}

func (tdc TestDbController) GetNonce(hashedNonce string, remoteAddress string, exp int64) (dbc.NonceDocument, error) {
	return tdc.nonceDoc, tdc.nonceDocErr
}

func (tdc TestDbController) AddNonce(hashedNonce string, remoteAddress string, time int64) error {
	return tdc.addNonceErr
}

func (tdc TestDbController) RemoveOldNonces(exp int64) error {
	return tdc.removeOldNoncesErr
}

func (tdc TestDbController) AddRequestLog(log *au.RequestLogData) error {
	return errors.New("Unimplemented")
}

func (tdc TestDbController) AddInfoLog(log *au.InfoLogData) error {
	return errors.New("Unimplemented")
}

func (tdc TestDbController) AddUser(userDoc dbc.FullUserDocument) error {
	return errors.New("Unimplemented")
}

func (tdc TestDbController) EditUser(userDoc dbc.EditUserDocument) error {
	return tdc.editUserErr
}

func (tdc TestDbController) EditUserPassword(userId string, passwordHash string) error {
	return tdc.editUserErr
}

func (tdc *TestDbController) SetInitDbErr(err error)                  { tdc.initDbErr = err }
func (tdc *TestDbController) SetUserDoc(userDoc dbc.FullUserDocument) { tdc.userDoc = userDoc }
func (tdc *TestDbController) SetUserDocErr(err error)                 { tdc.userDocErr = err }
func (tdc *TestDbController) SetNonceDoc(nonceDoc dbc.NonceDocument)  { tdc.nonceDoc = nonceDoc }
func (tdc *TestDbController) SetNonceDocErr(err error)                { tdc.nonceDocErr = err }
func (tdc *TestDbController) SetAddNonceErr(err error)                { tdc.addNonceErr = err }
func (tdc *TestDbController) SetRemoveOldNoncesErr(err error)         { tdc.removeOldNoncesErr = err }
func (tdc *TestDbController) SetEditUserError(err error)              { tdc.editUserErr = err }
