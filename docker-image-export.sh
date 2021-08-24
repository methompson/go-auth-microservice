cp ./keys ./docker/keys

(
  cd docker && \
  docker build -t auth-microservice . && \
  docker save auth-microservice -o auth-microservice.tar
)