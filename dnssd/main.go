package main

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"hapv2/crypto/srp"
	"hapv2/encoding/tlv8"
	"hapv2/pairing"

	"github.com/golang/glog"
	"github.com/kr/pretty"
	"golang.org/x/crypto/chacha20poly1305"

	_ "net/http/pprof"
)

var (
	curve25519 = ecdh.X25519()

	longTermPrivateKey, _ = hex.DecodeString("1bee047c1f94ee3742d37d7df85c3e2f841a28b89c1650f4c252b9081b705f9d0c793015345acc4171a132a178084b8846b01a6ea8e90bf48d4dbdfda4f88ecf")
	longTermPublicKey, _  = hex.DecodeString("0c793015345acc4171a132a178084b8846b01a6ea8e90bf48d4dbdfda4f88ecf")
	setupID               = "7OSX"
	deviceName            = "HAPv3"
	deviceID              = randomDeviceID()

	deviceInfo = &pairing.DeviceInfo{
		DeviceID:   deviceID,
		SetupCode:  10100101,
		PrivateKey: longTermPrivateKey,
		PublicKey:  longTermPublicKey,
	}
	registry = pairing.NewRegistry()
	setup    = pairing.NewSetupSession(deviceInfo, registry)
)

func main() {
	flag.Parse()

	// ln, err := net.ListenTCP("tcp", &net.TCPAddr{
	// 	Port: 8888,
	// })
	ln, err := net.ListenTCP("tcp", nil)
	if err != nil {
		log.Fatal(err)
	}
	args := []string{"-R", deviceName, "_hap._tcp",
		"local",
		strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
	}
	service := &Service{
		ConfigNumber:    1,
		DeviceID:        deviceID,
		Model:           deviceName,
		ProtocolVersion: "1.1",
		CategoryID:      2,
		StatusFlags:     StatusFlagNotPaired,
		SetupHash:       pairing.SetupHash(setupID, deviceID),
	}
	args = append(args, service.TextRecords()...)
	cmd := exec.Command("dns-sd", args...)
	cmd.Stdout = os.Stdout
	cmd.Start()

	svr := &http.Server{
		ConnState: func(c net.Conn, s http.ConnState) {
			glog.Info("ConnState", c, s)
			sc := c.(*serverConn)
			switch s {
			case http.StateIdle:
				sc.EnableEncryption()
			case http.StateClosed:
				ReleasePairingSession(c)
			}
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// glog.Info("ConnContext")
			return context.WithValue(ctx, contextKey, &Controller{
				conn: c,
			})
		},
	}
	err = svr.Serve(listener{ln})
	// err = svr.Serve(ln)
	if err != nil {
		log.Fatal(err)
	}
}

var knownPeers = pairing.NewRegistry()

type Controller struct {
	conn            net.Conn
	sharedSecret    []byte
	setupSessionKey []byte
	verifySession   *PairVerifySession
}

type PairingSession struct {
	mu         sync.Mutex
	owner      net.Conn
	state      pairing.State
	privateKey []byte
	ss         *srp.ServerSession
	salt       []byte
	sessionKey []byte
}

var pairingSession PairingSession

func init() {
	const pairingUsername = "Pair-Setup"
	// pairingSession.privateKey = srp.MustGeneratePrivateKey()
	// pairingSession.salt = srp.MustGenerateSalt()
	pairingSession.privateKey = make([]byte, 3072/8)
	pairingSession.salt = make([]byte, 16)
	sec := srp.NewSecret(pairingSession.salt, pairingUsername, "101-00-101")
	pairingSession.ss = srp.NewServerSession(pairingSession.privateKey, sec)
}

func AquirePairingSession(conn net.Conn) *PairingSession {
	pairingSession.mu.Lock()
	defer pairingSession.mu.Unlock()
	if pairingSession.owner == nil {
		pairingSession.owner = conn
	}
	if pairingSession.owner != conn {
		return nil
	}
	return &pairingSession
}

func ReleasePairingSession(conn net.Conn) {
	pairingSession.mu.Lock()
	defer pairingSession.mu.Unlock()
	if pairingSession.owner == conn {
		pairingSession.owner = nil
	}
}

var contextKey = struct{}{}

func FromContext(ctx context.Context) *Controller {
	return ctx.Value(contextKey).(*Controller)
}

type pairSetupRequest struct {
	State pairing.State `tlv:"06"`
}

func init() {
	http.HandleFunc("/pair-setup", pairSetup)
	http.HandleFunc("/pair-verify", pairVerify)
	http.HandleFunc("/pairings", pairEdit)
	http.HandleFunc("/accessories", getAccessories)
	http.HandleFunc("/characteristics", handleCharacteristics)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, err := httputil.DumpRequest(r, true)
		if err != nil {
			glog.Error(err)
			return
		}
		glog.Error(string(b))
	})
}

func writeTLV(w http.ResponseWriter, m any) {
	glog.InfoDepthf(1, "WRITE %#v", m)
	b, err := tlv8.Marshal(m)
	if err != nil {
		glog.Error(err)
		return
	}
	w.Write(b)
}

func randomDeviceID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5])
}

func pairSetup(w http.ResponseWriter, r *http.Request) {
	dumpTLVRequest(r)

	w.Header().Set("Content-Type", "application/pairing+tlv8")
	ctl := FromContext(r.Context())
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}

	ps := AquirePairingSession(ctl.conn)
	if ps == nil {
		// http.Error(w, "pairing session in use", http.StatusConflict)
		writeTLV(w, pairing.ErrorResponse{
			State: pairing.StateM2,
			Error: pairing.ErrorBusy,
		})
		return
	}

	pr := pairSetupRequest{}
	if err := tlv8.Unmarshal(b, &pr); err != nil {
		glog.Error(err)
		return
	}

	switch pr.State {
	case pairing.StateM1:
		var req pairing.SRPStartRequest
		if err := tlv8.Unmarshal(b, &req); err != nil {
			glog.Error(err)
			return
		}
		if req.Flags != 0 {
			glog.Error("invalid flags")
			return
		}
		writeTLV(w, pairing.SRPStartResponse{
			State:     pairing.StateM2,
			Salt:      ps.salt,
			PublicKey: ps.ss.PublicKey(),
			Flags:     req.Flags,
		})
	case pairing.StateM3:
		var req pairing.SRPVerifyRequest
		if err := tlv8.Unmarshal(b, &req); err != nil {
			glog.Error(err)
			return
		}
		// glog.Infof("%#v", req)
		K := ps.ss.SessionKey(req.PublicKey)
		if err := ps.ss.VerifyClientProof(K, req.PublicKey, req.Proof); err != nil {
			glog.Error(err)
			return
		}
		ctl.sharedSecret = K
		glog.Info("shared secret: %x", ctl.sharedSecret)
		writeTLV(w, pairing.SRPVerifyResponse{
			State: pairing.StateM4,
			Proof: ps.ss.Proof(K, req.PublicKey, req.Proof),
		})
	case pairing.StateM5:
		var req pairing.ExchangeRequest
		if err := tlv8.Unmarshal(b, &req); err != nil {
			glog.Error(err)
			return
		}
		// glog.Infof("%#v", req)
		sessionKey := pairing.DeriveKey(ctl.sharedSecret, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
		ctl.setupSessionKey = sessionKey
		aead, err := chacha20poly1305.New(sessionKey)
		if err != nil {
			glog.Error(err)
			return
		}
		submsg, err := aead.Open(nil, []byte("\x00\x00\x00\x00PS-Msg05"), req.EncryptedData, nil)
		if err != nil {
			glog.Error(err)
			return
		}
		var ctlInfo pairing.PairInfo
		if err := tlv8.Unmarshal(submsg, &ctlInfo); err != nil {
			glog.Error(err)
			return
		}
		// glog.Infof("ctl info: %#v", ctlInfo)
		deviceX := pairing.DeriveKey(ctl.sharedSecret, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
		if !ed25519.Verify(
			ctlInfo.LongTermPublicKey,
			bytes.Join([][]byte{deviceX, []byte(ctlInfo.PairingID), ctlInfo.LongTermPublicKey}, nil),
			ctlInfo.Signature,
		) {
			glog.Error("invalid signature")
			return
		}
		knownPeers.Add(&ctlInfo)
		accessoryX := pairing.DeriveKey(ctl.sharedSecret, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info")
		accInfo := pairing.PairInfo{
			PairingID:         deviceID,
			LongTermPublicKey: longTermPublicKey,
		}
		accInfo.Signature = ed25519.Sign(
			longTermPrivateKey,
			bytes.Join([][]byte{accessoryX, []byte(accInfo.PairingID), accInfo.LongTermPublicKey}, nil),
		)
		// glog.Infof("accessoryInfo: %#v", accInfo)
		submsg, err = tlv8.Marshal(accInfo)
		if err != nil {
			glog.Error(err)
			return
		}
		// glog.Infof("%x", submsg)
		writeTLV(w, pairing.ExchangeResponse{
			State:         pairing.StateM6,
			EncryptedData: aead.Seal(nil, []byte("\x00\x00\x00\x00PS-Msg06"), submsg, nil),
		})
	}
}

func pairVerify(w http.ResponseWriter, r *http.Request) {
	dumpTLVRequest(r)

	w.Header().Set("Content-Type", "application/pairing+tlv8")
	ctl := FromContext(r.Context())

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	pr := pairSetupRequest{}
	if err := tlv8.Unmarshal(b, &pr); err != nil {
		glog.Error(err)
		return
	}
	switch pr.State {
	case pairing.StateM1:
		var req pairing.VerifyStartRequest
		if err := tlv8.Unmarshal(b, &req); err != nil {
			glog.Error(err)
			return
		}
		vs, err := newPairVerifySession(req.PublicKey)
		if err != nil {
			glog.Error(err)
			return
		}
		ctl.verifySession = vs
		accInfo := pairing.PairInfo{
			PairingID: deviceID,
		}
		accInfo.Signature = ed25519.Sign(longTermPrivateKey, bytes.Join([][]byte{
			vs.privateKey.PublicKey().Bytes(),
			[]byte(accInfo.PairingID),
			req.PublicKey,
		}, nil))
		submsg, err := tlv8.Marshal(accInfo)
		if err != nil {
			glog.Error(err)
			return
		}
		writeTLV(w, pairing.VerifyStartResponse{
			State:         pairing.StateM2,
			PublicKey:     vs.privateKey.PublicKey().Bytes(),
			EncryptedData: vs.aead.Seal(nil, []byte("\x00\x00\x00\x00PV-Msg02"), submsg, nil),
		})
	case pairing.StateM3:
		var req pairing.VerifyFinishRequest
		if err := tlv8.Unmarshal(b, &req); err != nil {
			glog.Error(err)
			return
		}
		vs := ctl.verifySession
		submsg, err := vs.aead.Open(nil, []byte("\x00\x00\x00\x00PV-Msg03"), req.EncryptedData, nil)
		if err != nil {
			glog.Error(err)
			return
		}
		var ctlInfo pairing.PairInfo
		if err := tlv8.Unmarshal(submsg, &ctlInfo); err != nil {
			glog.Error(err)
			return
		}
		peer, ok := knownPeers.Get(ctlInfo.PairingID)
		if !ok {
			glog.Error("unknown pairing")
			return
		}
		if !ed25519.Verify(peer.LongTermPublicKey, bytes.Join([][]byte{
			vs.ctlPublicKey.Bytes(),
			[]byte(ctlInfo.PairingID),
			vs.privateKey.PublicKey().Bytes(),
		}, nil), ctlInfo.Signature) {
			glog.Error("invalid signature")
			return
		}
		writeTLV(w, pairing.VerifyFinishResponse{
			State: pairing.StateM4,
		})
		sc, ok := ctl.conn.(*serverConn)
		if ok {
			sc.SetEncryptionKey(vs.sharedSecret)
			glog.Info("encryption enabled")
		}
	}
}

type pairEditRequest struct {
	State  pairing.State  `tlv:"06"`
	Method pairing.Method `tlv:"00"`
}

func pairEdit(w http.ResponseWriter, r *http.Request) {
	dumpTLVRequest(r)

	w.Header().Set("Content-Type", "application/pairing+tlv8")

	// TODO: error handling

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	pr := pairEditRequest{}
	if err := tlv8.Unmarshal(b, &pr); err != nil {
		glog.Error(err)
		return
	}
	// TODO: error handling
	switch pr.Method {
	case pairing.MethodAdd:
		var req pairing.AddPairingRequest
		if err := tlv8.Unmarshal(b, &req); err != nil {
			glog.Error(err)
			return
		}
		// TODO: error handling
		if err := knownPeers.Add(&req.PairInfo); err != nil {
			glog.Error(err)
			return
		}
		writeTLV(w, pairing.AddPairingResponse{
			State: pairing.StateM2,
		})
	case pairing.MethodRemove:
		var req pairing.RemovePairingRequest
		if err := tlv8.Unmarshal(b, &req); err != nil {
			glog.Error(err)
			return
		}
		// TODO: error handling
		if err := knownPeers.Remove(req.PairingID); err != nil {
			glog.Error(err)
			return
		}
		writeTLV(w, pairing.RemovePairingResponse{
			State: pairing.StateM2,
		})
	case pairing.MethodList:
		var req pairing.ListPairingRequest
		if err := tlv8.Unmarshal(b, &req); err != nil {
			glog.Error(err)
			return
		}
		// TODO: error handling
		resp := pairing.ListPairingResponse{
			State: pairing.StateM2,
			Pairs: knownPeers.List(),
		}
		writeTLV(w, resp)
	default:
		// TODO
	}
}

func dumpTLVRequest(r *http.Request) {
	const depth = 1
	b, err := httputil.DumpRequest(r, false)
	if err != nil {
		glog.ErrorDepth(depth, err)
		return
	}
	glog.InfoDepthf(depth, "[%s] %s", r.RemoteAddr, b)
	b, err = io.ReadAll(r.Body)
	if err != nil {
		glog.ErrorDepth(depth, err)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	glog.InfoDepthf(depth, "%x", b)
	for tr := tlv8.NewReader(bytes.NewReader(b)); ; {
		it, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			glog.ErrorDepth(depth, err)
			return
		}
		glog.InfoDepthf(depth, "READ %#v", it)
	}
}

type PairVerifySession struct {
	ctlPublicKey *ecdh.PublicKey
	privateKey   *ecdh.PrivateKey
	sharedSecret []byte
	sessionKey   []byte
	aead         cipher.AEAD
}

func newPairVerifySession(pairPublicKey []byte) (*PairVerifySession, error) {
	pri, err := curve25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, err := curve25519.NewPublicKey(pairPublicKey)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := pri.ECDH(pub)
	if err != nil {
		return nil, err
	}
	sessionKey := pairing.DeriveKey(sharedSecret, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
	aead := pairing.MustNewChacha20Poly1305(sessionKey)
	return &PairVerifySession{
		ctlPublicKey: pub,
		privateKey:   pri,
		sharedSecret: sharedSecret,
		sessionKey:   sessionKey,
		aead:         aead,
	}, nil
}

type listener struct {
	net.Listener
}

func (l listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &serverConn{
		c:   c.(*net.TCPConn),
		rwc: c,
	}, nil
}

type serverConn struct {
	c   *net.TCPConn
	rwc io.ReadWriter

	mu        sync.Mutex
	encrypted int

	inboundMu    sync.Mutex
	inboundBuf   []byte
	inboundNonce uint64
	inbound      cipher.AEAD

	outboundMu    sync.Mutex
	outboundNonce uint64
	outbound      cipher.AEAD
}

func (c *serverConn) SetEncryptionKey(sharedSecret []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.encrypted > 0 {
		panic("already encrypted")
	}
	c.encrypted = 1
	inboundKey := pairing.DeriveKey(sharedSecret, "Control-Salt", "Control-Write-Encryption-Key")
	c.inbound = pairing.MustNewChacha20Poly1305(inboundKey)
	outboundKey := pairing.DeriveKey(sharedSecret, "Control-Salt", "Control-Read-Encryption-Key")
	c.outbound = pairing.MustNewChacha20Poly1305(outboundKey)
}

func (c *serverConn) EnableEncryption() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.encrypted == 1 {
		c.encrypted = 2
	}
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	encrypted := c.encrypted
	c.mu.Unlock()
	// glog.Infof("READ:%d encrypted:%t", len(b), encrypted)
	if encrypted == 2 {
		return c.readEncrypted(b)
	}
	return c.rwc.Read(b)
}

func (c *serverConn) readEncrypted(b []byte) (n int, err error) {
	c.inboundMu.Lock()
	defer c.inboundMu.Unlock()
	if c.inboundBuf == nil {
		b, err := c.readEncryptedFrame()
		if err != nil {
			return 0, err
		}
		c.inboundBuf = b
	}
	n = copy(b, c.inboundBuf)
	c.inboundBuf = c.inboundBuf[n:]
	if len(c.inboundBuf) == 0 {
		c.inboundBuf = nil
	}
	return n, nil
}

func (c *serverConn) readEncryptedFrame() ([]byte, error) {
	// 2 byte for length
	// encrypted data of length bytes (<= 1024)
	// auth tag of 16 bytes
	buf := make([]byte, 2+1024+16)
	aad := buf[:2]
	if _, err := io.ReadFull(c.rwc, aad); err != nil {
		// glog.Errorf("ReadFull: %v", err)
		return nil, err
	}
	l := binary.LittleEndian.Uint16(aad)
	if l > 1024 {
		return nil, errors.New("conn: invalid length")
	}
	msg := buf[2:][:l+16]
	if _, err := io.ReadFull(c.rwc, msg); err != nil {
		return nil, err
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.inboundNonce)
	cleartext, err := c.inbound.Open(msg[:0], nonce[:], msg, aad)
	if err != nil {
		glog.Errorf("inbound.Open: %v", err)
		return nil, err
	}
	c.inboundNonce++
	// glog.Infof("%s", cleartext)
	return cleartext, nil
}

func (c *serverConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	encrypted := c.encrypted
	c.mu.Unlock()
	// glog.Infof("WRITE:%d encrypted:%t", len(p), encrypted)
	if encrypted == 2 {
		return c.writeEncrypted(p)
	}
	return c.rwc.Write(p)
}

func (c *serverConn) writeEncrypted(p []byte) (int, error) {
	c.outboundMu.Lock()
	defer c.outboundMu.Unlock()
	written := 0
	for {
		data := p
		if len(data) == 0 {
			break
		}
		if len(data) > 1024 {
			data = data[:1024]
			p = p[1024:]
		} else {
			p = nil
		}
		if err := c.writeFrame(data); err != nil {
			return written, err
		}
		written += len(data)
	}
	return written, nil
}

func (c *serverConn) writeFrame(b []byte) error {
	// glog.Infof("WRITE FRAME %s", b)
	// 2 byte for length
	// encrypted data of length bytes (<= 1024)
	// auth tag of 16 bytes
	buf := make([]byte, 2+1024+16)
	aad := buf[:2]
	binary.LittleEndian.PutUint16(aad, uint16(len(b)))
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.outboundNonce)
	ciphertext := c.outbound.Seal(buf[2:][:0], nonce[:], b, aad)
	c.outboundNonce++
	_, err := c.rwc.Write(buf[:2+len(ciphertext)])
	return err
}

func (c *serverConn) CloseRead() error {
	return c.c.CloseRead()
}

func (c *serverConn) CloseWrite() error {
	return c.c.CloseWrite()
}

func (c *serverConn) Close() error {
	return c.c.Close()
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.c.LocalAddr()
}

func (c *serverConn) RemoteAddr() net.Addr {
	return c.c.RemoteAddr()
}

func (c *serverConn) SetDeadline(t time.Time) error {
	return c.c.SetDeadline(t)
}

func (c *serverConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c *serverConn) SetWriteDeadline(t time.Time) error {
	return c.c.SetWriteDeadline(t)
}

func getAccessories(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile("accessories.json")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/hap+json")
	w.Write(b)
}

func handleCharacteristics(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getCharacteriestics(w, r)
	case http.MethodPut:
		updateCharacteristics(w, r)
	}
}

type Permission string

const (
	PermissionPairedRead              Permission = "pr"
	PermissionPairedWrite             Permission = "pw"
	PermissionEvents                  Permission = "ev"
	PermissionAdditionalAuthorization Permission = "aa"
	PermissionTimedWrite              Permission = "tw"
	PermissionHidden                  Permission = "hd"
	PermissionWriteResponse           Permission = "wr"
)

type Format string

const (
	FormatBool   Format = "bool"
	FormatUint8  Format = "uint8"
	FormatUint16 Format = "uint16"
	FormatUint32 Format = "uint32"
	FormatUint64 Format = "uint64"
	FormatInt    Format = "int"   // int32
	FormatFloat  Format = "float" // float64
	FormatString Format = "string"
	FormatTLV8   Format = "tlv8" // []byte (base64 encoded)
	FormatData   Format = "data" // []byte (base64 encoded)
)

type Unit string

const (
	UnitCelsius    Unit = "celsius"
	UnitPercentage Unit = "percentage"
	UnitArcDegree  Unit = "arcdegrees"
	UnitLux        Unit = "lux"
	UnitSeconds    Unit = "seconds"
)

type CharacteristicDescriptor struct {
	Type               string   `json:"type"`
	Permissions        []string `json:"perms"`
	Value              any      `json:"value,omitempty"`
	EventNotifications bool     `json:"ev,omitempty"`
}

type CharacteristicMetadata struct {
	Format           Format    `json:"format"`
	Description      string    `json:"description,omitempty"`
	Unit             Unit      `json:"unit,omitempty"`
	MinValue         float64   `json:"minValue,omitempty"`
	MaxValue         float64   `json:"maxValue,omitempty"`
	StepValue        float64   `json:"minStep,omitempty"`
	MaxLength        uint64    `json:"maxLen,omitempty"`
	MaxDataLength    uint64    `json:"maxDataLen,omitempty"`
	ValidValues      []string  `json:"valid-values,omitempty"`
	ValidValuesRange []float64 `json:"valid-values-range,omitempty"`
}

type Characteristic struct {
	AID    uint64          `json:"aid"`
	IID    uint64          `json:"iid"`
	Value  json.RawMessage `json:"value"`
	Status int             `json:"status,omitempty"` // Output only
}

type UpdateCharacteristicsRequest struct {
	Characteristics []*Characteristic `json:"characteristics"`
}

type UpdateCharacteristicsResponse struct {
	Characteristics []*Characteristic `json:"characteristics"`
}

func updateCharacteristics(w http.ResponseWriter, r *http.Request) {
	var req UpdateCharacteristicsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	glog.Infof("updateCharacteristics: \n%s", pretty.Sprint(req))
	w.WriteHeader(http.StatusNoContent)
	// resp := &UpdateCharacteristicsResponse{
	// 	Characteristics: make([]*Characteristic, len(req.Characteristics)),
	// }
	// for i, c := range req.Characteristics {
	// 	resp.Characteristics[i] = &Characteristic{
	// 		AID:   c.AID,
	// 		IID:   c.IID,
	// 		Value: c.Value,
	// 	}
	// }
	// if err := json.NewEncoder(w).Encode(resp); err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }
}

type CharacteristicID struct {
	AID uint64 `json:"aid"`
	IID uint64 `json:"iid"`
}

type GetCharacteristicsRequest struct {
	IDs                   []CharacteristicID `query:"id"`
	IncludeMetaProperties bool               `query:"meta"`
	IncludePermsProperty  bool               `query:"perms"`
	IncludeTypeProperty   bool               `query:"type"`
	IncludeEventProperty  bool               `query:"ev"`
}

func parseGetCharacteristicsRequest(q url.Values) (*GetCharacteristicsRequest, error) {
	req := GetCharacteristicsRequest{
		IncludeMetaProperties: q.Get("meta") == "1",
		IncludePermsProperty:  q.Get("perms") == "1",
		IncludeTypeProperty:   q.Get("type") == "1",
		IncludeEventProperty:  q.Get("ev") == "1",
	}
	for _, t := range strings.Split(q.Get("id"), ",") {
		p := strings.SplitN(t, ".", 2)
		if len(p) != 2 {
			return nil, fmt.Errorf("invalid id: %q", t)
		}
		var id CharacteristicID
		var err error
		if id.AID, err = strconv.ParseUint(p[0], 10, 64); err != nil {
			return nil, err
		}
		if id.IID, err = strconv.ParseUint(p[1], 10, 64); err != nil {
			return nil, err
		}
		req.IDs = append(req.IDs, id)
	}
	return &req, nil
}

func getCharacteriestics(w http.ResponseWriter, r *http.Request) {
	req, err := parseGetCharacteristicsRequest(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	glog.Infof("getCharacteristics: \n%s", pretty.Sprint(req))
	_ = req
	w.WriteHeader(http.StatusOK)
}
