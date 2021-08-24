cp ./keys ./docker/keys

./compile-to-linux-release.sh

(
  cd docker && \
  docker build -t auth-microservice . && \
  docker save auth-microservice -o auth-microservice.tar
)