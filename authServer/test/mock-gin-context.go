package authServerTest

import (
	// "net/http/httptest"
	"net/http"

	"github.com/gin-gonic/gin"
)

func MakeTestContext() *gin.Context {
	req, _ := http.NewRequest("POST", "/login", nil)
	ctx := &gin.Context{}
	ctx.Request = req

	return ctx
}
