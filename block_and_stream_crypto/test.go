
package main

import (
	"fmt"
	"encoding/hex"
)

func main() {
	a := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	b := []byte{1, 2, 3}

	cip := RepeatedKeyXor(a, b)
	fmt.Println(cip)

	cip = SingleByteXor(a, 'k')
	fmt.Println(cip)

	hexstring := []byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	dst := make([]byte, hex.DecodedLen(len(hexstring)))
	hex.Decode(dst, hexstring)

	fmt.Println(string(dst))
	// break single byte xor
	key := BreakSingleByteXor(dst)
	fmt.Println(key)

	msg := SingleByteXor(dst, byte(88))
	fmt.Println(string(msg))

	res := characterScore("eeeä\x01")

	fmt.Println(res)
}
