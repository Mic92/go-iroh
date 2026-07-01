package quicvarint

import "testing"

var benchmarkVarintSink uint64

func BenchmarkAppendParse(b *testing.B) {
	values := []uint64{37, 15293, 1<<30 - 1, 1<<62 - 1}
	for _, v := range values {
		b.Run("append", func(b *testing.B) {
			buf := make([]byte, 0, Len(v))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf = Append(buf[:0], v)
			}
			benchmarkVarintSink = uint64(len(buf))
		})
		encoded := Append(nil, v)
		b.Run("parse", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				got, _, err := Parse(encoded)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkVarintSink = got
			}
		})
	}
}
