cp ./keys ./docker/keys
cp ./env ./docker/eng

(cd docker && docker build -t auth-microserver .)