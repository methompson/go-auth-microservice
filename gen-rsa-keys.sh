echo "Don't Add a passphrase"
mkdir keys
ssh-keygen -t rsa -b 4096 -m PEM -f ./keys/jwtRS256.key
openssl rsa -in ./keys/jwtRS256.key -pubout -outform PEM -out ./keys/jwtRS256.key.pub
cat ./keys/jwtRS256.key
cat ./keys/jwtRS256.key.pub