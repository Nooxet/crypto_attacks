package main

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"math"
	"strings"
)

/*
Helper function for AesCtr. Runs AES for one round to generate a block of keystream
*/
func aes_round(aes cipher.Block, nonce int, ctr int) []byte {
	iv := new(bytes.Buffer)
	// the nonce is the upper 64 bits, the counter is the lower 64 bits
	binary.Write(iv, binary.LittleEndian, int64(nonce))
	binary.Write(iv, binary.LittleEndian, int64(ctr))

	ctr_key := make([]byte, 16)
	aes.Encrypt(ctr_key, iv.Bytes())

	return ctr_key
}

/*
Encrypt a message with AES CTR under a key and nonce.
Returns the ciphertext.
*/
func AesCtr(aes cipher.Block, nonce int, message []byte) []byte {
	var res []byte
	var msg []byte
	var upper int

	for i, n := 0, int(math.Ceil(float64(len(message))/16)); i < n; i++ {

		ctr := aes_round(aes, nonce, i)

		upper = i*16 + 16
		if upper > len(message) {
			upper = len(message)
		}

		msg = message[i*16 : upper]

		// decrypt each block for as many bytes as in the msg
		for j, m := range msg {
			res = append(res, m^ctr[j])
		}
	}

	return res
}

func SingleByteXor(in []byte, key byte) []byte {
	inlen := len(in)
	out := make([]byte, inlen)

	for i := 0; i < inlen; i++ {
		out[i] = in[i] ^ key
	}

	return out
}

func RepeatedKeyXor(in []byte, key []byte) []byte {
	keylen := len(key)
	inlen := len(in)
	out := make([]byte, inlen)

	for i := 0; i < inlen; i++ {
		out[i] = in[i] ^ key[i % keylen]
	}

	return out
}

func characterScore(text string) float64 {
	freqs := map[string]float64{
    "A": 0.0651738,
    "B": 0.0124248,
    "C": 0.0217339,
    "D": 0.0349835,
    "E": 0.1041442,
    "F": 0.0197881,
    "G": 0.0158610,
    "H": 0.0492888,
    "I": 0.0558094,
    "J": 0.0009033,
    "K": 0.0050529,
    "L": 0.0331490,
    "M": 0.0202124,
    "N": 0.0564513,
    "O": 0.0596302,
    "P": 0.0137645,
    "Q": 0.0008606,
    "R": 0.0497563,
    "S": 0.0515760,
    "T": 0.0729357,
    "U": 0.0225134,
    "V": 0.0082903,
    "W": 0.0171272,
    "X": 0.0013692,
    "Y": 0.0145984,
    "Z": 0.0007836,
    " ": 0.1918182,
	}

	score := 0.0
	for _, c := range strings.ToUpper(text) {
		// check if freqs contains c, otherwise just skip it
		if val, ok := freqs[string(c)]; ok {
			score += val
		}
	}

	return score
}

/*
Break cipher encrypted with a single byte xor statistically,
comparing against the english alphabet frequency.
Returns the key most likely to decrypt the message.
*/
func BreakSingleByteXor(cip []byte) byte {
	max := 0.0
	key := 0
	for i := 0; i < 256; i++ {
		msg := SingleByteXor(cip, byte(i))
		score := characterScore(string(msg))
		if score > max {
			max = score
			key = i
		}
	}

	return byte(key)
}
