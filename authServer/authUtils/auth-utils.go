package authUtils

import (
	"encoding/hex"
	"net"
	"os"
	"strconv"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"

	"methompson.com/auth-microservice/authServer/constants"
)

var hashCost = 14

func SetHashCost() {
	definedCost := os.Getenv(constants.HASH_COST)
	conv, convErr := strconv.Atoi(definedCost)

	if convErr != nil {
		return
	}

	hashCost = conv
}

// Takes a string, converts to bytes and finds the sha3-512 hash from the
// bytes of that string.
func HashString(str string) string {
	strBytes := []byte(str)
	return HashBytes(strBytes)
}

// Takes an array of bytes and calculates the sha3-512 hash of the bytes array
func HashBytes(bytes []byte) string {
	// Hash the value using sha3-512
	hasher := sha3.New512()
	hasher.Write(bytes)
	sum := hasher.Sum(nil)

	sha3Str := hex.EncodeToString(sum)

	return sha3Str
}

func HashPassword(pass string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(pass), hashCost)
	return string(bytes), err
}

func CheckPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GetRemoteAddressIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)

	if err != nil {
		return remoteAddr
	}

	return host
}
