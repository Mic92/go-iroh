// Package postcard encodes and decodes the Rust postcard wire format.
package postcard

import (
	"encoding"
	"errors"
	"fmt"
	"math"
	"reflect"
	"unicode/utf8"
)

// Marshaler is implemented by values with a custom postcard representation.
type Marshaler interface {
	MarshalPostcard() ([]byte, error)
}

var (
	// ErrTrailingBytes is returned when Unmarshal does not consume all input.
	ErrTrailingBytes = errors.New("postcard: trailing bytes")
	errShort         = errors.New("postcard: truncated input")
)

// Marshal encodes v in postcard format.
func Marshal(v any) ([]byte, error) {
	var e encoder
	if err := e.value(reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	return e.b, nil
}

// Unmarshal decodes postcard data into v.
func Unmarshal(data []byte, v any) error {
	if v == nil {
		return errors.New("postcard: nil target")
	}
	d := decoder{b: data}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("postcard: target must be non-nil pointer")
	}
	if err := d.value(rv.Elem()); err != nil {
		return err
	}
	if d.off != len(d.b) {
		return ErrTrailingBytes
	}
	return nil
}

type encoder struct {
	b []byte
}

func (e *encoder) value(v reflect.Value) error {
	if !v.IsValid() {
		return errors.New("postcard: invalid value")
	}
	if v.Kind() == reflect.Interface && !v.IsNil() {
		v = v.Elem()
	}
	if v.CanInterface() {
		if m, ok := v.Interface().(Marshaler); ok {
			b, err := m.MarshalPostcard()
			if err != nil {
				return err
			}
			e.b = append(e.b, b...)
			return nil
		}
		if tm, ok := v.Interface().(encoding.TextMarshaler); ok && v.Kind() == reflect.String {
			b, err := tm.MarshalText()
			if err != nil {
				return err
			}
			return e.bytes(b)
		}
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return errors.New("postcard: nil pointer")
		}
		return e.value(v.Elem())
	case reflect.Bool:
		if v.Bool() {
			e.b = append(e.b, 1)
		} else {
			e.b = append(e.b, 0)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		e.b = appendVarint(e.b, v.Uint())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		e.b = appendVarint(e.b, zigzag(v.Int()))
	case reflect.String:
		return e.bytes([]byte(v.String()))
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			for i := 0; i < v.Len(); i++ {
				e.b = append(e.b, byte(v.Index(i).Uint()))
			}
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := e.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if v.IsNil() {
			e.b = appendVarint(e.b, 0)
			return nil
		}
		e.b = appendVarint(e.b, uint64(v.Len()))
		if v.Type().Elem().Kind() == reflect.Uint8 {
			e.b = append(e.b, v.Bytes()...)
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := e.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).PkgPath != "" {
				continue
			}
			if err := e.value(v.Field(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("postcard: unsupported type %s", v.Type())
	}
	return nil
}

func (e *encoder) bytes(b []byte) error {
	e.b = appendVarint(e.b, uint64(len(b)))
	e.b = append(e.b, b...)
	return nil
}

type decoder struct {
	b   []byte
	off int
}

func (d *decoder) value(v reflect.Value) error {
	if !v.CanSet() {
		return fmt.Errorf("postcard: cannot set %s", v.Type())
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		return d.value(v.Elem())
	case reflect.Bool:
		x, err := d.byte()
		if err != nil {
			return err
		}
		switch x {
		case 0:
			v.SetBool(false)
		case 1:
			v.SetBool(true)
		default:
			return fmt.Errorf("postcard: invalid bool %d", x)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		x, err := d.varint()
		if err != nil {
			return err
		}
		if v.OverflowUint(x) {
			return fmt.Errorf("postcard: %d overflows %s", x, v.Type())
		}
		v.SetUint(x)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		x, err := d.varint()
		if err != nil {
			return err
		}
		i := unzigzag(x)
		if v.OverflowInt(i) {
			return fmt.Errorf("postcard: %d overflows %s", i, v.Type())
		}
		v.SetInt(i)
	case reflect.String:
		b, err := d.bytes()
		if err != nil {
			return err
		}
		if !utf8.Valid(b) {
			return fmt.Errorf("postcard: invalid utf-8 string")
		}
		v.SetString(string(b))
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if d.off+v.Len() > len(d.b) {
				return errShort
			}
			reflect.Copy(v, reflect.ValueOf(d.b[d.off:d.off+v.Len()]))
			d.off += v.Len()
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := d.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		n, err := d.varint()
		if err != nil {
			return err
		}
		if n > uint64(len(d.b)-d.off) && v.Type().Elem().Kind() == reflect.Uint8 {
			return errShort
		}
		if n > uint64(math.MaxInt) {
			return fmt.Errorf("postcard: sequence too large")
		}
		s := reflect.MakeSlice(v.Type(), int(n), int(n))
		if v.Type().Elem().Kind() == reflect.Uint8 {
			reflect.Copy(s, reflect.ValueOf(d.b[d.off:d.off+int(n)]))
			d.off += int(n)
			v.Set(s)
			return nil
		}
		for i := 0; i < int(n); i++ {
			if err := d.value(s.Index(i)); err != nil {
				return err
			}
		}
		v.Set(s)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).PkgPath != "" {
				continue
			}
			if err := d.value(v.Field(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("postcard: unsupported type %s", v.Type())
	}
	return nil
}

func (d *decoder) byte() (byte, error) {
	if d.off >= len(d.b) {
		return 0, errShort
	}
	x := d.b[d.off]
	d.off++
	return x, nil
}

func (d *decoder) bytes() ([]byte, error) {
	n, err := d.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(d.b)-d.off) {
		return nil, errShort
	}
	b := d.b[d.off : d.off+int(n)]
	d.off += int(n)
	return b, nil
}

func (d *decoder) varint() (uint64, error) {
	x, n, err := readVarint(d.b[d.off:])
	if err != nil {
		return 0, err
	}
	d.off += n
	return x, nil
}

func appendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func readVarint(buf []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(buf); i++ {
		if i >= 10 {
			break
		}
		b := buf[i]
		if i == 9 && b > 1 {
			return 0, 0, fmt.Errorf("postcard: varint overflow")
		}
		v |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errShort
}

func zigzag(v int64) uint64 {
	return uint64(v<<1) ^ uint64(v>>63)
}

func unzigzag(v uint64) int64 {
	return int64(v>>1) ^ -int64(v&1)
}
