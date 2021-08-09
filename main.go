package main

import (
	"syscall"

	"methompson.com/auth-microservice/authServer"
)

func main() {
	syscall.Umask(0)
	authServer.StartServer()
}
