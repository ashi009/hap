package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"strconv"

	"hapv2/crypto/ipsession"
	"hapv2/pairing"

	"github.com/golang/glog"

	_ "net/http/pprof"
)

var (
	longTermPrivateKey, _ = hex.DecodeString("1bee047c1f94ee3742d37d7df85c3e2f841a28b89c1650f4c252b9081b705f9d0c793015345acc4171a132a178084b8846b01a6ea8e90bf48d4dbdfda4f88ecf")
	longTermPublicKey, _  = hex.DecodeString("0c793015345acc4171a132a178084b8846b01a6ea8e90bf48d4dbdfda4f88ecf")
	setupID               = "7OSX"
	deviceName            = "HAPv3"

	deviceInfo = &pairing.DeviceInfo{
		DeviceID:   randomDeviceID(),
		SetupCode:  10100101,
		PrivateKey: longTermPrivateKey,
		PublicKey:  longTermPublicKey,
	}
	registry = pairing.NewRegistry()
	setup    = pairing.NewSetupSession(deviceInfo, registry)
)

func main() {
	flag.Parse()

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
		DeviceID:        deviceInfo.DeviceID,
		Model:           deviceName,
		ProtocolVersion: "1.1",
		CategoryID:      2,
		StatusFlags:     StatusFlagNotPaired,
		SetupHash:       pairing.SetupHash(setupID, deviceInfo.DeviceID),
	}
	args = append(args, service.TextRecords()...)
	cmd := exec.Command("dns-sd", args...)
	cmd.Stdout = os.Stdout
	cmd.Start()

	// qr := pairing.SetupPayload{
	// 	Version:           0,
	// 	AccessoryCategory: 2,
	// 	IPTransport:       true,
	// 	SetupCode:         deviceInfo.SetupCode,
	// 	SetupID:           setupID,
	// }.QR()

	// fmt.Println("Scan this code with your HomeKit app on your iOS device to pair with this device:")
	// for i := 0; i < qr.Size; i++ {
	// 	for j := 0; j < qr.Size; j++ {
	// 		if qr.Black(i, j) {
	// 			fmt.Print("  ")
	// 		} else {
	// 			fmt.Print("██")
	// 		}
	// 	}
	// 	fmt.Println()
	// }

	svr := &http.Server{
		ConnState: func(c net.Conn, s http.ConnState) {
			glog.Infof("%s: %v conn ", c.RemoteAddr(), s)
			sc := c.(*serverConn)
			sc.HandleStateChange(s)
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return pairing.WithConn(ctx, c.(*serverConn))
		},
	}
	err = svr.Serve(listener{ln})
	// err = svr.Serve(ln)
	if err != nil {
		glog.Exit(err)
	}
}

func init() {
	http.HandleFunc("/pair-setup", logHandler(pairSetup))
	http.HandleFunc("/pair-verify", logHandler(pairVerify))
	http.HandleFunc("/pairings", logHandler(pairEdit))
	http.HandleFunc("/accessories", logHandler(getAccessories))
	http.HandleFunc("/characteristics", logHandler(handleCharacteristics))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, err := httputil.DumpRequest(r, true)
		if err != nil {
			glog.Errorf("%s: %v", r.RemoteAddr, err)
			return
		}
		glog.Error(string(b))
	})
}

func logHandler(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		glog.Infof("%s: %s %v", r.RemoteAddr, r.Method, r.URL)
		fn(w, r)
	}
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
	b, err := io.ReadAll(r.Body)
	if err != nil {
		glog.Errorf("%s: %v", r.RemoteAddr, err)
		return
	}
	ctx := r.Context()
	rb, err := setup.Handle(ctx, b)
	if err != nil {
		glog.Errorf("%s: %v", r.RemoteAddr, err)
		return
	}
	w.Header().Set("Content-Type", "application/pairing+tlv8")
	w.Write(rb)
}

func pairVerify(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		glog.Errorf("%s: %v", r.RemoteAddr, err)
		return
	}
	ctx := r.Context()
	ctl, _ := pairing.FromContext(ctx)
	conn := ctl.(*serverConn)
	rb, err := conn.vs.Handle(ctx, b)
	if err != nil {
		glog.Errorf("%s: %v", r.RemoteAddr, err)
		return
	}
	w.Header().Set("Content-Type", "application/pairing+tlv8")
	w.Write(rb)
}

func pairEdit(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		glog.Errorf("%s: %v", r.RemoteAddr, err)
		return
	}
	rb, err := registry.Handle(r.Context(), b)
	if err != nil {
		glog.Errorf("%s: %v", r.RemoteAddr, err)
		return
	}
	w.Header().Set("Content-Type", "application/pairing+tlv8")
	w.Write(rb)
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
		Conn: c,

		vs: pairing.NewVerifySession(deviceInfo, registry),
	}, nil
}

type serverConn struct {
	net.Conn
	nextConn net.Conn

	vs *pairing.VerifySession
}

func (c *serverConn) HandleStateChange(s http.ConnState) {
	switch s {
	case http.StateIdle:
		if c.nextConn != nil {
			c.Conn = c.nextConn
			c.nextConn = nil
			glog.Info("upgraded connection")
		}
	}
}

func (c *serverConn) Upgrade(sharedSecret []byte) {
	c.nextConn = ipsession.NewEncryptedConn(c.Conn, sharedSecret)
}

func (c *serverConn) Authenticated() bool {
	_, ok := c.Conn.(*ipsession.EncryptedConn)
	return ok
}
