// Package tlv8 implements a TLV8 marshaler and unmarshaler.
package tlv8

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
)

var (
	ErrMalformat       = errors.New("tlv8: malformat")
	ErrIntegerOverflow = errors.New("tlv8: integer overflow")
)

const fragmentSize = 255

// Item is a tlv8 item.
type Item struct {
	Type  uint8
	Value []byte
}

// Reader reads tlv8 stream.
type Reader struct {
	r      io.Reader
	peeked *Item
}

// NewReader returns a new reader that reads from r.
func NewReader(r io.Reader) *Reader {
	return &Reader{
		r: r,
	}
}

func (r *Reader) peek() (*Item, error) {
	if r.peeked != nil {
		return r.peeked, nil
	}
	var hdr [2]byte
	if _, err := io.ReadFull(r.r, hdr[:]); err != nil {
		return nil, err
	}
	t, l := hdr[0], hdr[1]
	buf := make([]byte, l)
	if _, err := io.ReadFull(r.r, buf); err != nil {
		return nil, err
	}
	r.peeked = &Item{
		Type:  t,
		Value: buf,
	}
	return r.peeked, nil
}

func (r *Reader) advance() {
	r.peeked = nil
}

// Next returns the next item in the stream.
func (r *Reader) Next() (*Item, error) {
	item, err := r.peek()
	if err != nil {
		return nil, err
	}
	r.advance()
	for {
		nitem, err := r.peek()
		if err == io.EOF {
			return item, nil
		}
		if err != nil {
			return nil, err
		}
		if nitem.Type != item.Type {
			return item, nil
		}
		if len(item.Value)%fragmentSize != 0 { // all previous fregments must be full 255-byte
			return nil, ErrMalformat
		}
		item.Value = append(item.Value, nitem.Value...)
		r.advance()
	}
}

// Encode encodes the given data to tlv8 stream.
type Encoder struct {
	w io.Writer
}

// NewEncoder returns a new encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{
		w: w,
	}
}

func (e *Encoder) Write(item Item) error {
	next := item.Value
	for {
		seg := next
		if len(seg) > fragmentSize {
			seg = seg[:fragmentSize]
		}
		next = next[len(seg):]
		if _, err := e.w.Write([]byte{item.Type, byte(len(seg))}); err != nil {
			return err
		}
		if _, err := e.w.Write(seg); err != nil {
			return err
		}
		if len(next) == 0 {
			break
		}
	}
	return nil
}

func decodeVarUint(data []byte) (uint64, error) {
	if len(data) > 8 {
		return 0, ErrIntegerOverflow
	}
	var x uint64
	for i, b := range data {
		x |= uint64(b) << (i * 8)
	}
	return x, nil
}

func encodeVarUint(d uint64) []byte {
	var res []byte
	for d > 0 {
		res = append(res, byte(d))
		d >>= 8
	}
	return res
}

func Unmarshal(data []byte, p any) error {
	rv := reflect.ValueOf(p)
	if rv.Kind() != reflect.Ptr {
		return errors.New("not a pointer")
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return errors.New("not a struct")
	}
	rt := rv.Type()
	// TODO: cache the decoders for each type.
	m := make(map[byte][]int)
	for _, rf := range reflect.VisibleFields(rt) {
		if rf.Anonymous {
			continue
		}
		typ, err := strconv.ParseUint(rf.Tag.Get("tlv"), 16, 8)
		if err != nil {
			return err
		}
		m[byte(typ)] = rf.Index
	}
	r := NewReader(bytes.NewReader(data))
	for {
		item, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		fidx, ok := m[item.Type]
		if !ok {
			continue
		}
		v := rv.FieldByIndex(fidx)
		switch v.Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			i, err := decodeVarUint(item.Value)
			if err != nil {
				return err
			}
			if v.OverflowUint(i) {
				return ErrIntegerOverflow
			}
			v.SetUint(i)
		case reflect.String:
			v.SetString(string(item.Value))
		case reflect.Slice:
			v.SetBytes(item.Value)
		default:
			panic(fmt.Errorf("unspported type: %s", v.Type()))
		}
	}
	return nil
}

func Marshal(p any) ([]byte, error) {
	rv := reflect.ValueOf(p)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, errors.New("not a struct")
	}
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	rt := rv.Type()
	for _, rf := range reflect.VisibleFields(rt) {
		typ, err := strconv.ParseUint(rf.Tag.Get("tlv"), 16, 8)
		if err != nil {
			return nil, err
		}
		v := rv.FieldByIndex(rf.Index)
		switch v.Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if err := enc.Write(Item{
				Type:  byte(typ),
				Value: encodeVarUint(v.Uint()),
			}); err != nil {
				return nil, err
			}
		case reflect.String:
			if err := enc.Write(Item{
				Type:  byte(typ),
				Value: []byte(v.String()),
			}); err != nil {
				return nil, err
			}
		case reflect.Slice:
			if v.Type().Elem().Kind() == reflect.Uint8 {
				if err := enc.Write(Item{
					Type:  byte(typ),
					Value: v.Bytes(),
				}); err != nil {
					return nil, err
				}
				break
			}
			for i := 0; i < v.Len(); i++ {
				if i > 0 {
					if err := enc.Write(Item{
						Type: byte(typ),
					}); err != nil {
						return nil, err
					}
				}
				item := v.Index(i)
				b, err := Marshal(item.Interface())
				if err != nil {
					return nil, err
				}
				if _, err := buf.Write(b); err != nil {
					return nil, err
				}
			}
		default:
			panic(fmt.Errorf("unspported type: %s", v.Type()))
		}
	}
	return buf.Bytes(), nil
}
