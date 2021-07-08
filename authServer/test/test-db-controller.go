package authServerTest

import (
	"methompson.com/auth-microservice/authServer"
)

type TestDbController struct {
	initDbErr          error
	userDoc            authServer.UserDocument
	userDocErr         error
	nonceDoc           authServer.NonceDocument
	nonceDocErr        error
	addNonceErr        error
	removeOldNoncesErr error
}

func (tdc TestDbController) InitDatabase() error {
	return tdc.initDbErr
}

func (tdc TestDbController) GetUserByUsername(username string, password string) (authServer.UserDocument, error) {
	return tdc.userDoc, tdc.userDocErr
}

func (tdc TestDbController) GetNonce(hashedNonce string, remoteAddress string) (authServer.NonceDocument, error) {
	return tdc.nonceDoc, tdc.nonceDocErr
}

func (tdc TestDbController) AddNonce(hashedNonce string, remoteAddress string) error {
	return tdc.addNonceErr
}

func (tdc TestDbController) RemoveOldNonces() error {
	return tdc.removeOldNoncesErr
}

func (tdc TestDbController) SetInitDbErr(err error)                        { tdc.initDbErr = err }
func (tdc TestDbController) SetUserDoc(userDoc authServer.UserDocument)    { tdc.userDoc = userDoc }
func (tdc TestDbController) SetUserDocErr(err error)                       { tdc.userDocErr = err }
func (tdc TestDbController) SetNonceDoc(nonceDoc authServer.NonceDocument) { tdc.nonceDoc = nonceDoc }
func (tdc TestDbController) SetNonceDocErr(err error)                      { tdc.nonceDocErr = err }
func (tdc TestDbController) SetAddNonceErr(err error)                      { tdc.addNonceErr = err }
func (tdc TestDbController) SetRemoveOldNoncesErr(err error)               { tdc.removeOldNoncesErr = err }

func MakeBlankTestDbController() TestDbController {
	return TestDbController{
		nil,
		authServer.UserDocument{},
		nil,
		authServer.NonceDocument{},
		nil,
		nil,
		nil,
	}
}
