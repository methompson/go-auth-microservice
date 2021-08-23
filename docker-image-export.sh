cp ./keys ./docker/keys
cp ./env ./docker/eng

(
  cd docker && \
  docker build -t auth-microservice . && \
  docker save auth-microservice -o auth-microservice.tar
)