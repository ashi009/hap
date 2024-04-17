package hapv2

import (
	"net"
	"net/http"

	"hapv2/pairing"
)

type listener struct {
}

type serverConn struct {
	net.Conn
	nextConn net.Conn

	// pairingSession *pairing.SetupSession
	vs *pairing.VerifySession
}

func (c *serverConn) HandleStateChange(_ net.Conn, s http.ConnState) {
	switch s {
	case http.StateIdle:
		if c.nextConn != nil {
			c.Conn = c.nextConn
			c.nextConn = nil
		}
	}
}
