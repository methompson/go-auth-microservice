echo "Don't Add a passphrase"
mkdir -p authServer/test/keys
ssh-keygen -t rsa -b 4096 -m PEM -f ./authServer/test/keys/jwtRS256.key
openssl rsa -in ./authserver/test/keys/jwtRS256.key -pubout -outform PEM -out ./authServer/test/keys/jwtRS256.key.pub
cat ./authServer/test/keys/jwtRS256.key
cat ./authServer/test/keys/jwtRS256.key.pub