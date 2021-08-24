cp -R ./keys ./docker/keys

(
  cd docker && \
  docker build -t auth-microservice .
)