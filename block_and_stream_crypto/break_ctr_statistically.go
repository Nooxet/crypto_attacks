/*
Code for breaking AES in CTR mode with fixed nonce using
frequency analysis.
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
	// find the length of the minimum message
	trunclen := 1000
	for scanner.Scan() {
		msg, _ := base64.StdEncoding.DecodeString(scanner.Text())
		if len(msg) < trunclen {
			trunclen = len(msg)
		}
		cip := AesCtr(aes, nonce, msg)
		cips = append(cips, cip)
	}

	// truncate att ciphers to the minimum length
	for i := 0; i < len(cips); i++ {
		cips[i] = cips[i][:trunclen]
	}

	// transpose the ciphertexts to create new strings xor:ed with the same key
	var cipsT [][]byte
	var newcip []byte
	for char := 0; char < trunclen; char++ {
		newcip = nil
		for c := 0; c < len(cips); c++ {
			// get character "char" from cipher "c"
			newcip = append(newcip, cips[c][char])
		}
		cipsT = append(cipsT, newcip)
	}

	// break each transposed ciphertext using frequency analysis
	keystream := make([]byte, trunclen)
	for i := 0; i < len(cipsT); i++ {
		keystream[i] = BreakSingleByteXor(cipsT[i])
	}

	// decrypt and print the ciphertexts
	// it won't be perfect, but almost
	for i := 0; i < len(cips); i++ {
		plain := RepeatedKeyXor(cips[i], keystream)
		fmt.Println(string(plain))
	}
}
