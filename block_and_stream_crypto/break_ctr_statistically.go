/*
Code for breaking AES in CTR mode with fixed nonce using
manual substitution. Trying bigrams and trigrams etc.
*/

package main

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
)

func check(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	file, err := os.Open("break_ctr_statistically.input")
	check(err)
	defer file.Close()

	// set up AES with a random key and fixed nonce
	rand.Seed(42)
	nonce := 0
	key := make([]byte, 16)
	rand.Read(key)
	fmt.Println(key)
	aes, _ := aes.NewCipher(key)

	var cips [][]byte
	scanner := bufio.NewScanner(file)
	// read one line at a time, decode it and encrypt it
	for scanner.Scan() {
		msg, _ := base64.StdEncoding.DecodeString(scanner.Text())
		cip := AesCtr(aes, nonce, msg)
		cips = append(cips, cip)
	}

	fmt.Println(cips)
}
