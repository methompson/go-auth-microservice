package authServerTest

import (
	"errors"

	dbc "methompson.com/auth-microservice/authServer/dbController"
)

type TestDbController struct {
	initDbErr          error
	userDoc            dbc.UserDocument
	userDocErr         error
	nonceDoc           dbc.NonceDocument
	nonceDocErr        error
	addNonceErr        error
	removeOldNoncesErr error
}

func (tdc TestDbController) InitDatabase() error {
	return tdc.initDbErr
}

func (tdc TestDbController) GetUserByUsername(username string, passwordHash string) (dbc.UserDocument, error) {
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

func (tdc TestDbController) AddRequestLog(log dbc.RequestLogData) error {
	return errors.New("Unimplemented")
}
func (tdc TestDbController) AddErrorLog(log dbc.ErrorLogData) error {
	return errors.New("Unimplemented")
}

func (tdc TestDbController) AddUser(username string, password string, enabled bool) error {
	return errors.New("Unimplemented")
}
func (tdc TestDbController) EditUser(username string, password string, enabled bool) error {
	return errors.New("Unimplemented")
}

func (tdc *TestDbController) SetInitDbErr(err error)                 { tdc.initDbErr = err }
func (tdc *TestDbController) SetUserDoc(userDoc dbc.UserDocument)    { tdc.userDoc = userDoc }
func (tdc *TestDbController) SetUserDocErr(err error)                { tdc.userDocErr = err }
func (tdc *TestDbController) SetNonceDoc(nonceDoc dbc.NonceDocument) { tdc.nonceDoc = nonceDoc }
func (tdc *TestDbController) SetNonceDocErr(err error)               { tdc.nonceDocErr = err }
func (tdc *TestDbController) SetAddNonceErr(err error)               { tdc.addNonceErr = err }
func (tdc *TestDbController) SetRemoveOldNoncesErr(err error)        { tdc.removeOldNoncesErr = err }

func MakeBlankTestDbController() TestDbController {
	return TestDbController{
		nil,
		dbc.UserDocument{},
		nil,
		dbc.NonceDocument{},
		nil,
		nil,
		nil,
	}
}
