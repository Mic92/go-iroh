package quicvarint

import (
	"bytes"
	"testing"
)

func FuzzParse(f *testing.F) {
	for _, n := range []uint64{0, 63, 64, 16383, 16384, 1073741823, Max} {
		f.Add(Append(nil, n))
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = Parse(data)
		_, _ = Read(bytes.NewReader(data))
	})
}
