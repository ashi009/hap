package pairing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"

	"hapv2/crypto/cryptoutil"
	"hapv2/crypto/srp"
	"hapv2/encoding/tlv8"

	"github.com/golang/glog"
)

type DeviceInfo struct {
	DeviceID   string
	SetupCode  SetupCode
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// SetupSession handles the accessory-side pair setup.
type SetupSession struct {
	di         *DeviceInfo
	knownPeers *Registry

	state        State
	ss           *srp.ServerSession
	sharedSecret []byte

	mu    sync.Mutex
	owner Conn
}

func NewSetupSession(di *DeviceInfo, r *Registry) *SetupSession {
	return &SetupSession{
		di:         di,
		knownPeers: r,

		state: StateM1,
	}
}

func (s *SetupSession) Handle(ctx context.Context, req []byte) ([]byte, error) {
	var pr pairSetupRequest
	if err := tlv8.Unmarshal(req, &pr); err != nil {
		return nil, err
	}
	switch pr.State {
	case StateM1:
		return call(s.handleSRPStart, req)
	case StateM3:
		return call(s.handleSRPVerify, req)
	case StateM5:
		return call(s.handleExchange, req)
	default:
		return nil, fmt.Errorf("unexpected state: %v", pr.State)
	}
}

func (s *SetupSession) acquireOwner(c Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner != nil {
		return fmt.Errorf("owner already set")
	}
	s.owner = c
	return nil
}

func (s *SetupSession) assertOwner(c Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner != c {
		return fmt.Errorf("not owner")
	}
	return nil
}

func (s *SetupSession) releaseOwner(c Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner != c {
		return fmt.Errorf("not owner")
	}
	s.owner = nil
	return nil
}

func call[Req, Resp any](fn func(*Req) (*Resp, error), b []byte) ([]byte, error) {
	var req Req
	if err := tlv8.Unmarshal(b, &req); err != nil {
		return nil, err
	}
	glog.Infof("-> %#v", req)
	resp, err := fn(&req)
	if err != nil {
		return nil, err
	}
	glog.Infof("<- %#v", resp)
	return tlv8.Marshal(resp)
}

func (s *SetupSession) handleSRPStart(req *SRPStartRequest) (*SRPStartResponse, error) {
	privateKey := srp.MustGeneratePrivateKey()
	salt := srp.MustGenerateSalt()
	sec := srp.NewSecret(salt, "Pair-Setup", s.di.SetupCode.String())
	s.ss = srp.NewServerSession(privateKey, sec)
	return &SRPStartResponse{
		State:     StateM2,
		Salt:      salt,
		PublicKey: s.ss.PublicKey(),
		Flags:     req.Flags,
	}, nil
}

func (s *SetupSession) handleSRPVerify(req *SRPVerifyRequest) (*SRPVerifyResponse, error) {
	K := s.ss.SessionKey(req.PublicKey)
	if err := s.ss.VerifyClientProof(K, req.PublicKey, req.Proof); err != nil {
		return nil, err
	}
	s.sharedSecret = K
	return &SRPVerifyResponse{
		State: StateM4,
		Proof: s.ss.Proof(K, req.PublicKey, req.Proof),
	}, nil
}

func (s *SetupSession) handleExchange(req *ExchangeRequest) (*ExchangeResponse, error) {
	sessionKey := cryptoutil.DeriveKey(s.sharedSecret, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
	aead := cryptoutil.MustNewChacha20Poly1305(sessionKey)
	submsg, err := aead.Open(nil, []byte("\x00\x00\x00\x00PS-Msg05"), req.EncryptedData, nil)
	if err != nil {
		return nil, err
	}
	var ctlInfo PairInfo
	if err := tlv8.Unmarshal(submsg, &ctlInfo); err != nil {
		return nil, err
	}
	deviceX := cryptoutil.DeriveKey(s.sharedSecret, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
	if !ed25519.Verify(ctlInfo.LongTermPublicKey, bytes.Join([][]byte{
		deviceX,
		[]byte(ctlInfo.PairingID),
		ctlInfo.LongTermPublicKey,
	}, nil), ctlInfo.Signature) {
		return nil, fmt.Errorf("invalid signature")
	}
	s.knownPeers.Add(&ctlInfo)
	accessoryX := cryptoutil.DeriveKey(s.sharedSecret, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info")
	accInfo := PairInfo{
		PairingID:         s.di.DeviceID,
		LongTermPublicKey: s.di.PublicKey,
		Signature: ed25519.Sign(s.di.PrivateKey, bytes.Join([][]byte{
			accessoryX,
			[]byte(s.di.DeviceID),
			s.di.PublicKey,
		}, nil)),
	}
	submsg, err = tlv8.Marshal(accInfo)
	if err != nil {
		return nil, err
	}
	return &ExchangeResponse{
		State:         StateM6,
		EncryptedData: aead.Seal(nil, []byte("\x00\x00\x00\x00PS-Msg06"), submsg, nil),
	}, nil
}
