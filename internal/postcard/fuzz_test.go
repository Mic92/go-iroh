package postcard

import "testing"

type fuzzPostcard struct {
	A uint64
	B int64
	C bool
	D string
	E []byte
	F *uint16
}

func FuzzUnmarshal(f *testing.F) {
	seed, err := Marshal(fuzzPostcard{A: 1, B: -2, C: true, D: "hello", E: []byte{1, 2, 3}, F: ptr(uint16(9))})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		var v fuzzPostcard
		_ = Unmarshal(data, &v)
	})
}

func ptr[T any](v T) *T { return &v }
