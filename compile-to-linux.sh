rm -rf ./docker/bin
mkdir docker/bin
env GOOS=linux go build -o ./docker/bin/auth-microserver