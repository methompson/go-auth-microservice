# go-auth-microservice
### Simple microservice for handling basic authentication.

This project is designed to be a standalone application whose only purpose is to handle authentication tasks.

This project will do the following:
* Generate nonce values
* Authenticate user credentials
* Return JWT authorization tokens encoded using a public key crypto system.

The purpose of this project is to provide authentication services for a larger project. These services will help decouple the auth services from a larger project. It will provide public APIs that allow clients as well as other web services to interact with the auth service.

The public key crypto system allows other microservices to easily confirm the validity of JWTs by using the service's public key.

The current implementation is started with the intent of using MongoDB as the database back end. The project may, eventually, become expandable to use any database.

This project is purely academic and should not be considered a serious service.

To Test use the following command:

`go test ./authServer/test`