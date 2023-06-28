package srp

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var ErrInvalidProof = errors.New("srp: invalid proof")

func genRandom(sz int) ([]byte, error) {
	buf := make([]byte, sz)
	_, err := io.ReadFull(rand.Reader, buf)
	return buf, err
}

func mustGenRandom(sz int) []byte {
	buf, err := genRandom(sz)
	if err != nil {
		panic(fmt.Errorf("failed to generate random %d bytes: %v", sz, err))
	}
	return buf
}

// GeneratePrivateKey generates a private key.
func GeneratePrivateKey() ([]byte, error) {
	return genRandom(rfc5054_3072.Size())
}

// MustGeneratePrivateKey generates a private key.
func MustGeneratePrivateKey() []byte {
	return mustGenRandom(rfc5054_3072.Size())
}

// GenerateSalt generates a salt.
func GenerateSalt() ([]byte, error) {
	return genRandom(16)
}

// MustGenerateSalt generates a salt.
func MustGenerateSalt() []byte {
	return mustGenRandom(16)
}

// Secret is a SRP secret.
type Secret struct {
	salt     []byte
	username string
	x        *big.Int
}

// NewSecret returns a new secret.
func NewSecret(salt []byte, username, password string) *Secret {
	return &Secret{
		salt:     salt,
		username: username,
		x:        genX(salt, username, password),
	}
}

// ServerSession is a server-side SRP session.
type ServerSession struct {
	privateKey *big.Int
	publicKey  *big.Int
	secret     *Secret
	v          *big.Int
}

// NewServerSession returns a new server session.
func NewServerSession(privateKey []byte, s *Secret) *ServerSession {
	pk := new(big.Int).SetBytes(pad(privateKey))
	v := genV(s.x)
	return &ServerSession{
		privateKey: pk,
		publicKey:  genServerPublicKey(pk, v),
		secret:     s,
		v:          v,
	}
}

// PublicKey returns the public key of the server.
func (ss *ServerSession) PublicKey() []byte {
	return ss.publicKey.Bytes()
}

// SessionKey returns the session key of SRP session.
func (ss *ServerSession) SessionKey(clientPublicKey []byte) []byte {
	return genSessionKey(genServerSidePremasterSecret(new(big.Int).SetBytes(clientPublicKey), ss.privateKey, ss.publicKey, ss.v))
}

// VerifyClientProof verifies the client proof.
func (ss *ServerSession) VerifyClientProof(sessionKey, clientPublicKey, clientProof []byte) error {
	M := genClientProof(ss.secret.salt, ss.secret.username, clientPublicKey, ss.PublicKey(), sessionKey)
	if subtle.ConstantTimeCompare(clientProof, M) == 0 {
		return ErrInvalidProof
	}
	return nil
}

// Proof returns the server proof. The clientProof MUST be verified by VerifyClientProof first.
func (ss *ServerSession) Proof(sessionKey, clientPublicKey, clientProof []byte) []byte {
	return genServerProof(clientPublicKey, clientProof, sessionKey)
}

// ClientSession is a client-side SRP session.
type ClientSession struct {
	privateKey *big.Int
	publicKey  *big.Int
	secret     *Secret
}

// NewClientSession returns a new client session.
func NewClientSession(privateKey []byte, x *Secret) *ClientSession {
	pk := new(big.Int).SetBytes(privateKey)
	return &ClientSession{
		privateKey: pk,
		publicKey:  genClientPublicKey(pk),
		secret:     x,
	}
}

// PublicKey returns the public key of the client.
func (cs *ClientSession) PublicKey() []byte {
	return cs.publicKey.Bytes()
}

// SessionKey returns the session key of SRP session.
func (cs *ClientSession) SessionKey(serverPublicKey []byte) []byte {
	return genSessionKey(genClientSidePremasterSecret(cs.privateKey, cs.publicKey, new(big.Int).SetBytes(serverPublicKey), cs.secret.x))
}

// Proof returns the proof of the client.
func (cs *ClientSession) Proof(sessionKey, serverPublicKey []byte) []byte {
	return genClientProof(cs.secret.salt, cs.secret.username, cs.PublicKey(), serverPublicKey, sessionKey)
}

// VerifyServerProof verifies the server proof.
func (cs *ClientSession) VerifyServerProof(sessionKey, clientProof, serverProof []byte) error {
	sa := genServerProof(cs.PublicKey(), clientProof, sessionKey)
	if subtle.ConstantTimeCompare(sa, serverProof) == 0 {
		return ErrInvalidProof
	}
	return nil
}
