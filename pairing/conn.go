package pairing

import "context"

// This file contains the implementation of the encrypted conn.

type contextKey struct{}

type Conn interface {
	Upgrade(sharedSecret []byte)
	Authenticated() bool
}

func WithConn(ctx context.Context, c Conn) context.Context {
	return context.WithValue(ctx, contextKey{}, c)
}

func FromContext(ctx context.Context) (Conn, bool) {
	c, ok := ctx.Value(contextKey{}).(Conn)
	return c, ok
}
