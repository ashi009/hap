package ipsession

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	cryptotuil "hapv2/crypto/cryptoutil"
	"io"
	"net"
	"sync"

	"github.com/golang/glog"
)

const (
	frameLengthBytes     = 2
	framePayloadMaxBytes = 1024
	frameTagBytes        = 16
	frameMaxBytes        = frameLengthBytes + framePayloadMaxBytes + frameTagBytes

	nonceBytes      = 12
	nonceFixedBytes = 4
)

// EncryptedConn is an established accessory-side encrypted connection.
type EncryptedConn struct {
	net.Conn
	w frameWriter
	r frameReader
}

// NewEncryptedConn returns a new encrypted connection.
func NewEncryptedConn(c net.Conn, sharedSecret []byte) *EncryptedConn {
	ec := &EncryptedConn{
		Conn: c,
		w:    frameWriter{w: c},
		r:    frameReader{r: c},
	}
	crKey := cryptotuil.DeriveKey(sharedSecret, "Control-Salt", "Control-Read-Encryption-Key")
	ec.w.aead = cryptotuil.MustNewChacha20Poly1305(crKey)
	cwKey := cryptotuil.DeriveKey(sharedSecret, "Control-Salt", "Control-Write-Encryption-Key")
	ec.r.aead = cryptotuil.MustNewChacha20Poly1305(cwKey)
	return ec
}

func (c *EncryptedConn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *EncryptedConn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

// frameWriter is a frame-based writer.
type frameWriter struct {
	w    io.Writer
	aead cipher.AEAD

	mu  sync.Mutex
	seq [nonceBytes]byte
}

func (fw *frameWriter) Write(p []byte) (int, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	written := 0
	for {
		l := len(p)
		if l == 0 {
			break
		}
		if l > framePayloadMaxBytes {
			l = framePayloadMaxBytes
		}
		if err := fw.writeFrame(p[:l]); err != nil {
			return written, err
		}
		written += l
		p = p[l:]
	}
	return written, nil
}

func (fw *frameWriter) writeFrame(claertext []byte) error {
	var frame [frameMaxBytes]byte
	aad := frame[:frameLengthBytes]
	binary.LittleEndian.PutUint16(aad, uint16(len(claertext)))
	ciphertext := fw.aead.Seal(frame[frameLengthBytes:][:0], fw.seq[:], claertext, aad)
	binary.LittleEndian.PutUint64(fw.seq[nonceFixedBytes:],
		binary.LittleEndian.Uint64(fw.seq[nonceFixedBytes:])+1)
	_, err := fw.w.Write(frame[:frameLengthBytes+len(ciphertext)])
	return err
}

// frameReader is a frame-based reader.
type frameReader struct {
	r    io.Reader
	aead cipher.AEAD

	mu  sync.Mutex
	seq [nonceBytes]byte
	buf []byte
}

func (fr *frameReader) Read(b []byte) (n int, err error) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	if fr.buf == nil {
		b, err := fr.readFrame()
		glog.Infof("read frame: %s, %v", b, err)
		if err != nil {
			return 0, err
		}
		fr.buf = b
	}
	n = copy(b, fr.buf)
	fr.buf = fr.buf[n:]
	if len(fr.buf) == 0 {
		fr.buf = nil
	}
	return n, nil
}

func (fr *frameReader) readFrame() ([]byte, error) {
	var frame [frameMaxBytes]byte
	aad := frame[:frameLengthBytes]
	if _, err := io.ReadFull(fr.r, aad); err != nil {
		return nil, err
	}
	l := binary.LittleEndian.Uint16(aad)
	if l > framePayloadMaxBytes {
		return nil, fmt.Errorf("conn: frame payload too large: %d", l)
	}
	ciphertext := frame[frameLengthBytes:][:l+frameTagBytes]
	if _, err := io.ReadFull(fr.r, ciphertext); err != nil {
		return nil, err
	}
	cleartext, err := fr.aead.Open(ciphertext[:0], fr.seq[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("conn: failed to decrypt frame: %w", err)
	}
	binary.LittleEndian.PutUint64(fr.seq[nonceFixedBytes:],
		binary.LittleEndian.Uint64(fr.seq[nonceFixedBytes:])+1)
	return cleartext, nil
}
