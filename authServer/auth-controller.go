package authServer

import "github.com/gin-gonic/gin"

type AuthController interface {
	InitDatabase() error
	GenerateNonce(ctx *gin.Context) (string, error)
	LogUserIn(body LoginBody, ctx *gin.Context) (string, error)
	GetNonceFromDb(hashedNonce string, remoteAddress string) (NonceDocument, error)
	RemoveUsedNonce(hashedNonce string) error
}
