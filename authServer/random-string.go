package authServer

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
)

// Generate a random string of n bits length. 64 bits is a good starting point for
// generating a somewhat secure value. We return both a base 64 encoded string and
// the actual bytes. The string is, eventually returned to the client and the bytes
// are used for hashing the value and saving to the database. We could just return
// the base 64 encoded string and use a base 64 decoder, but returning the bytes
// representation should save a few ops
func GenerateRandomString(bits int) (string, []byte) {
	byt := make([]byte, bits)
	_, randReadErr := rand.Read(byt)

	if randReadErr != nil {
		errLog := fmt.Sprintln("Random Generator Error ", randReadErr)
		fmt.Println(errLog)
		log.Fatal(errLog)
	}

	b64 := base64.URLEncoding.EncodeToString(byt)

	return b64, byt
}
