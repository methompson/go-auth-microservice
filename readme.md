# go-auth-microservice
## Simple microservice for handling basic authentication.

This project is designed to be a standalone application whose only purpose is to handle authentication tasks.

This project will do the following:
* Generate nonce values
* Authenticate user credentials
* Return JWT authorization tokens encoded using a public key crypto system.

The purpose of this project is to provide authentication services for a larger project. These services will help decouple the auth services from a larger project. It will provide public APIs that allow clients as well as other web services to interact with the auth service.

The public key crypto system allows other microservices to easily confirm the validity of JWTs by using the service's public key.

The current implementation is started with the intent of using MongoDB as the database back end. The project may, eventually, become expandable to use any database.

This project is purely academic and should not be considered a serious service.

## Installation And Running

After pulling the source code from the Git repository, run the following command to load all dependencies.

`go get ./`

The first step running the application is to run `gen-rsa-keys.sh`. This generates the RSA keys needed for signing JWTs.

To run the application, you can run:

`go run .`

This command will build the program and run it.

To build a binary, you can run the following command:

`go build .`

To Test use the following command:

`go test ./authServer/test`

A Nodemon configuration has also been implemented written to aid in continuous development. This configuration uses the Nodemon package from NPM to monitor Go files and re-compile and re-run the application every time you make a change. To use this functionality, you'll need to have NPM installed. Run the following scripts to install all packages and run Nodemon:

```
npm i
npm run start
```