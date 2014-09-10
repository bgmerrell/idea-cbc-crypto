package main

import (
	"log"
	"strings"

	"github.com/shanemhansen/gossl/evp"
)

const CIPHER_NAME = "idea-cbc"

var key []byte = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
var iv []byte = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

// DecodeSiteCode returns a string representation of a site ID given an
// idea-cbc encrypted, base64 encoded, site code.
func main() {
	evp.OpenSSLAddAllCiphers()
	ctx := evp.NewCipherCtx()
	c := evp.CipherByName(CIPHER_NAME)
	if c == nil {
		log.Fatal("No cipher for " + CIPHER_NAME)
	}
	e := ctx.EncryptInit(c, key, iv)
	if e != nil {
		log.Fatal("Encrypt is required")
	}
	out := make([]byte, 8*2)
	in := []byte{0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x34, 0x32}
	n, err := ctx.EncryptUpdate(out, in)
	if err != nil {
		log.Fatal("error encrypting: ", err)
	}
	tmplength, err := ctx.EncryptFinal(out[n:])
	if err != nil {
		log.Fatal("error encrypting: ", err)
	}
	out = out[:n+tmplength]
	ctx.DecryptInit(c, key, iv)
	in = out
	out = make([]byte, 8*2)
	n1, err := ctx.DecryptUpdate(out, in)
	if err != nil {
		log.Fatal("error decrypt update: ", err)
	}
	n, err = ctx.DecryptFinal(out[:n1])
	out = out[:(n1 + n)]
	if err != nil {
		log.Fatal("error decrypt final: ", err)
	}
	if strings.TrimSpace(string(out)) != "42" {
		log.Fatalf("Got: %s, want: %s", strings.TrimSpace(string(out)), "42")
	} else {
		log.Println("Success!")
	}
}
