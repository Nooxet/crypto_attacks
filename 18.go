package main

import (
	"./utils"
	"crypto/aes"
	"encoding/base64"
	"fmt"
)

func main() {
	nonce := 0
	key := []byte("YELLOW SUBMARINE")
	block, _ := aes.NewCipher(key)

	msg_enc := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	msg_dec, _ := base64.StdEncoding.DecodeString(msg_enc)

	res := utils.AesCtr(block, nonce, msg_dec)
	fmt.Println(string(res))
}
