package srp

import (
	"crypto/sha512"
	"math/big"
)

var newH = sha512.New

func hash(b []byte) []byte {
	h := newH()
	h.Write(b)
	return h.Sum(nil)
}

func pad(b []byte) []byte {
	res := make([]byte, rfc5054_3072.Size())
	copy(res[len(res)-len(b):], b)
	return res
}

var k = genK()

func genK() *big.Int {
	// k = H(N | Pad(B))
	h := newH()
	h.Write(rfc5054_3072.N.Bytes())
	h.Write(pad(rfc5054_3072.G.Bytes()))
	return new(big.Int).SetBytes(h.Sum(nil))
}

func genX(salt []byte, username, password string) *big.Int {
	// x = H(salt | H(username | ':' | password))
	h := newH()
	h.Write([]byte(username))
	h.Write([]byte(":"))
	h.Write([]byte(password))
	up := h.Sum(nil)
	h.Reset()
	h.Write(salt)
	h.Write(up)
	return new(big.Int).SetBytes(h.Sum(up[:0]))
}

func genV(x *big.Int) *big.Int {
	// v = g^x % N
	return new(big.Int).Exp(rfc5054_3072.G, x, rfc5054_3072.N)
}

func genU(A, B *big.Int) *big.Int {
	// U = H(Pad(A) | Pad(B))
	h := newH()
	h.Write(pad(A.Bytes()))
	h.Write(pad(B.Bytes()))
	return new(big.Int).SetBytes(h.Sum(nil))
}

func genServerPublicKey(b, v *big.Int) *big.Int {
	// B = (kv + g^b) % N
	kv := new(big.Int).Mul(k, v)
	gb := new(big.Int).Exp(rfc5054_3072.G, b, rfc5054_3072.N)
	B := new(big.Int).Add(gb, kv)
	return B.Mod(B, rfc5054_3072.N)
}

func genClientPublicKey(a *big.Int) *big.Int {
	// A = g^a % N
	return new(big.Int).Exp(rfc5054_3072.G, a, rfc5054_3072.N)
}

func genServerSidePremasterSecret(A, b, B, v *big.Int) *big.Int {
	// S = (A * v^u) ^ b % N
	u := genU(A, B)
	vu := new(big.Int).Exp(v, u, rfc5054_3072.N)
	avu := new(big.Int).Mul(A, vu)
	return new(big.Int).Exp(avu, b, rfc5054_3072.N)
}

func genClientSidePremasterSecret(a, A, B, x *big.Int) *big.Int {
	// S = (B - (k * g^x)) ^ (a + (u * x)) % N
	u := genU(A, B)
	gx := new(big.Int).Exp(rfc5054_3072.G, x, rfc5054_3072.N)
	kgx := new(big.Int).Mul(k, gx)
	Bkgx := new(big.Int).Sub(B, kgx)
	ux := new(big.Int).Mul(u, x)
	aux := new(big.Int).Add(a, ux)
	return new(big.Int).Exp(Bkgx, aux, rfc5054_3072.N)
}

func genSessionKey(S *big.Int) []byte {
	// K = H(S)
	return hash(S.Bytes())
}

func genClientProof(salt []byte, username string, A, B, K []byte) []byte {
	// M = H(H(N) xor H(g) | H(I) | s | A | B | K)
	hn := hash(rfc5054_3072.N.Bytes())
	hg := hash(rfc5054_3072.G.Bytes())
	hng := new(big.Int).Xor(new(big.Int).SetBytes(hn), new(big.Int).SetBytes(hg))
	hi := hash([]byte(username))
	h := newH()
	h.Write(hng.Bytes())
	h.Write(hi[:])
	h.Write(salt)
	h.Write(A)
	h.Write(B)
	h.Write(K)
	return h.Sum(nil)
}

func genServerProof(A, M, K []byte) []byte {
	h := newH()
	h.Write(A)
	h.Write(M)
	h.Write(K)
	return h.Sum(nil)
}
