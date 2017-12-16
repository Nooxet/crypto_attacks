
package main

import (
	"math/big"
	"fmt"
	"math/rand"
)

func main() {
	// public values
	g := big.NewInt(2)
	p_str := "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"

	p := big.NewInt(0)
	p.SetString(p_str, 16)

	src := rand.NewSource(0)
	r := rand.New(src)

	// calculate Alice's "public" key
	x := big.NewInt(0).Rand(r, p)
	a := big.NewInt(0)
	a.Exp(g, x, p)

	// calculate Bob's "public" key
	y := big.NewInt(0).Rand(r, p)
	b := big.NewInt(0)
	b.Exp(g, y, p)

	// calculate the shared key
	s := big.NewInt(0)
	s.Exp(a, y, p)

	// this should yield the same result as s
	t := big.NewInt(0)
	t.Exp(b, x, p)

	fmt.Println(s, s.Cmp(t) == 0)
}
