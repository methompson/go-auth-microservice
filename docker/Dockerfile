FROM alpine:3.14
# FROM golang:1.16

RUN mkdir -p /srv/auth
WORKDIR /srv/auth

COPY bin/auth-microservice ./auth-microservice
COPY keys ./keys
COPY .env .

CMD ["./auth-microservice"]