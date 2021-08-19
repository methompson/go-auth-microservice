package authServer

import (
	"os"

	"methompson.com/auth-microservice/authServer/constants"
)

func DebugMode() bool {
	return os.Getenv(constants.GIN_MODE) != "release"
}

type LoginBody struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Nonce    string `json:"nonce" binding:"required"`
}

type AddUserBody struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	Enabled  bool   `json:"enabled"`
	Admin    bool   `json:"admin"`
	Nonce    string `json:"nonce" binding:"required"`
}

type EditUserBody struct {
	Id       string  `json:"id" binding:"required"`
	Username *string `json:"username"`
	Email    *string `json:"email"`
	Enabled  *bool   `json:"enabled"`
	Admin    *bool   `json:"admin"`
	Nonce    string  `json:"nonce" binding:"required"`
}

type EditPasswordBody struct {
	Id          string `json:"id" binding:"required"`
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword" binding:"required"`
	Nonce       string `json:"nonce" binding:"required"`
}

type AuthorizationHeader struct {
	Token string `header:"authorization" binding:"required"`
}
