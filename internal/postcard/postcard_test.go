package postcard

import (
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

type bag struct {
	N     uint64
	I     int64
	OK    bool
	Name  string
	Bytes []byte
	Fixed [4]byte
}

type blobFormat uint64

const (
	blobRaw blobFormat = iota
	blobHashSeq
)

type hashAndFormat struct {
	Hash   [32]byte
	Format blobFormat
}

type announceKind uint64

const (
	announcePartial announceKind = iota
	announceComplete
)

type absoluteTime uint64

type announce struct {
	Host      [32]byte
	Content   hashAndFormat
	Kind      announceKind
	Timestamp absoluteTime
}

type queryFlags struct {
	Complete bool
	Verified bool
}

type query struct {
	Content hashAndFormat
	Flags   queryFlags
}

func TestRustVectors(t *testing.T) {
	var fixed [4]byte
	copy(fixed[:], []byte{9, 8, 7, 6})
	var host [32]byte
	for i := range host {
		host[i] = byte(i)
	}
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(0xa0 + i)
	}
	content := hashAndFormat{Hash: hash, Format: blobHashSeq}

	tests := []struct {
		name string
		v    any
		hex  string
	}{
		{name: "u64", v: uint64(624485), hex: "e58e26"},
		{name: "i64", v: int64(-12345), hex: "f1c001"},
		{name: "bool", v: true, hex: "01"},
		{name: "string", v: "hello", hex: "0568656c6c6f"},
		{name: "bytes", v: []byte{1, 2, 3, 4}, hex: "0401020304"},
		{name: "fixed", v: fixed, hex: "09080706"},
		{
			name: "bag",
			v:    bag{N: 624485, I: -12345, OK: true, Name: "hello", Bytes: []byte{1, 2, 3, 4}, Fixed: fixed},
			hex:  "e58e26f1c001010568656c6c6f040102030409080706",
		},
		{
			name: "hash and format",
			v:    content,
			hex:  "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf01",
		},
		{
			name: "announce",
			v: announce{
				Host:      host,
				Content:   content,
				Kind:      announceComplete,
				Timestamp: absoluteTime(1_700_000_000_123_456),
			},
			hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
				"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
				"0101c0c480c1c1c48203",
		},
		{
			name: "query",
			v:    query{Content: content, Flags: queryFlags{Complete: true, Verified: false}},
			hex:  "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf010100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Marshal(tt.v)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if hex.EncodeToString(got) != tt.hex {
				t.Fatalf("Marshal = %x, want %s", got, tt.hex)
			}

			dst := reflect.New(reflect.TypeOf(tt.v)).Interface()
			if err := Unmarshal(got, dst); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !reflect.DeepEqual(reflect.ValueOf(dst).Elem().Interface(), tt.v) {
				t.Fatalf("round trip = %#v, want %#v", reflect.ValueOf(dst).Elem().Interface(), tt.v)
			}
		})
	}
}

func TestUnmarshalErrors(t *testing.T) {
	var u uint64
	if err := Unmarshal([]byte{0x80}, &u); !errors.Is(err, errShort) {
		t.Fatalf("short varint error = %v", err)
	}
	if err := Unmarshal([]byte{0, 1}, &u); !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("trailing error = %v", err)
	}
	var b bool
	if err := Unmarshal([]byte{2}, &b); err == nil {
		t.Fatal("Unmarshal accepted invalid bool")
	}
	var s string
	if err := Unmarshal([]byte{1, 0xff}, &s); err == nil {
		t.Fatal("Unmarshal accepted invalid UTF-8")
	}
}
