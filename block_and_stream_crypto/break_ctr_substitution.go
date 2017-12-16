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
	file, err := os.Open("break_ctr_substitution.input")
	check(err)
	defer file.Close()

	// set up AES with a random key and fixed nonce
	rand.Seed(1337)
	nonce := 0
	key := make([]byte, 16)
	rand.Read(key)
	fmt.Println(key)
	aes, _ := aes.NewCipher(key)

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	var line string = lines[0]
	msg, _ := base64.StdEncoding.DecodeString(line)

	res := AesCtr(aes, nonce, msg)
	fmt.Println(res)
}
