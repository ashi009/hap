package pairing

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"hapv2/crypto/cryptoutil"
	"hapv2/encoding/tlv8"

	"github.com/golang/glog"
)

var curve25519 = ecdh.X25519()

// VerifySession handles the accessory-side pair verify.
type VerifySession struct {
	di         *DeviceInfo
	knownPeers *Registry

	state        State
	privateKey   *ecdh.PrivateKey
	ctlPublicKey *ecdh.PublicKey
	sharedSecret []byte
	aead         cipher.AEAD
}

func NewVerifySession(di *DeviceInfo, r *Registry) *VerifySession {
	pri, err := curve25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &VerifySession{
		di:         di,
		knownPeers: r,

		state:      StateM1,
		privateKey: pri,
	}
}

type pairSetupRequest struct {
	State State `tlv:"06"`
}

func (s *VerifySession) Handle(ctx context.Context, req []byte) ([]byte, error) {
	conn, ok := FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no conn found in context")
	}
	var pr pairSetupRequest
	if err := tlv8.Unmarshal(req, &pr); err != nil {
		return nil, err
	}
	switch pr.State {
	case StateM1:
		var sreq VerifyStartRequest
		if err := tlv8.Unmarshal(req, &sreq); err != nil {
			return nil, err
		}
		sresp, err := s.handleStart(conn, &sreq)
		if err != nil {
			return nil, err
		}
		return tlv8.Marshal(sresp)
	case StateM3:
		var sreq VerifyFinishRequest
		if err := tlv8.Unmarshal(req, &sreq); err != nil {
			return nil, err
		}
		sresp, err := s.handleFinish(conn, &sreq)
		if err != nil {
			return nil, err
		}
		return tlv8.Marshal(sresp)
	default:
		return nil, fmt.Errorf("unknown state: %d", pr.State)
	}
}

func (s *VerifySession) handleStart(conn Conn, req *VerifyStartRequest) (*VerifyStartResponse, error) {
	pub, err := curve25519.NewPublicKey(req.PublicKey)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := s.privateKey.ECDH(pub)
	if err != nil {
		return nil, err
	}
	s.ctlPublicKey = pub
	s.sharedSecret = sharedSecret
	sessionKey := cryptoutil.DeriveKey(sharedSecret, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
	s.aead = cryptoutil.MustNewChacha20Poly1305(sessionKey)
	submsg, err := tlv8.Marshal(PairInfo{
		PairingID: s.di.DeviceID,
		Signature: ed25519.Sign(s.di.PrivateKey, bytes.Join([][]byte{
			s.privateKey.PublicKey().Bytes(),
			[]byte(s.di.DeviceID),
			req.PublicKey,
		}, nil)),
	})
	if err != nil {
		panic(err)
	}
	return &VerifyStartResponse{
		State:         StateM2,
		PublicKey:     s.privateKey.PublicKey().Bytes(),
		EncryptedData: s.aead.Seal(nil, []byte("\x00\x00\x00\x00PV-Msg02"), submsg, nil),
	}, nil
}

func (s *VerifySession) handleFinish(conn Conn, req *VerifyFinishRequest) (*VerifyFinishResponse, error) {
	submsg, err := s.aead.Open(nil, []byte("\x00\x00\x00\x00PV-Msg03"), req.EncryptedData, nil)
	if err != nil {
		return nil, err
	}
	var ctlInfo PairInfo
	if err := tlv8.Unmarshal(submsg, &ctlInfo); err != nil {
		return nil, err
	}
	peer, ok := s.knownPeers.Get(ctlInfo.PairingID)
	if !ok {
		return nil, fmt.Errorf("unknown peer: %s", ctlInfo.PairingID)
	}
	if !ed25519.Verify(peer.LongTermPublicKey, bytes.Join([][]byte{
		s.ctlPublicKey.Bytes(),
		[]byte(ctlInfo.PairingID),
		s.privateKey.PublicKey().Bytes(),
	}, nil), ctlInfo.Signature) {
		return nil, fmt.Errorf("invalid key")
	}
	glog.Infof("%s: upgrade with shared secret %x", ctlInfo.PairingID, s.sharedSecret)
	conn.Upgrade(s.sharedSecret)
	return &VerifyFinishResponse{
		State: StateM4,
	}, nil
}
