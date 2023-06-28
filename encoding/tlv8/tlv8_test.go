// Package tlv8 implements a TLV8 marshaler and unmarshaler.
package tlv8

import (
	"bytes"
	"io"
	"testing"
)

var data = []byte{0x07, 0x01, 0x03, 0x01, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f}

type X struct {
	State      byte   `tlv:"07"`
	Identifier string `tlv:"01"`
}

func TestX(t *testing.T) {
	r := NewReader(bytes.NewReader(data))
	for {
		item, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Error(err)
			break
		}
		t.Log(item)
	}
	t.Fail()
}

func TestUnmarshal(t *testing.T) {
	var x X
	Unmarshal(data, &x)
	t.Errorf("%#v", x)
}

func TestMarshal(t *testing.T) {
	x := X{
		State:      3,
		Identifier: "hello",
	}
	b, err := Marshal(x)
	t.Errorf("%x %v", b, err)
}

func TestMarshal2(t *testing.T) {
	type T struct {
		B []byte `tlv:"00"`
	}
	x := T{
		B: make([]byte, 10000),
	}
	b, err := Marshal(&x)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("%x", b)
	var y T
	if err := Unmarshal(b, &y); err != nil {
		t.Error(err)
		return
	}
}
