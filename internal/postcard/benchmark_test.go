package postcard

import "testing"

type benchmarkPostcardMessage struct {
	Kind    uint8
	Counter uint64
	Topic   string
	Data    []byte
}

var benchmarkPostcardSink benchmarkPostcardMessage

func BenchmarkMarshalUnmarshal(b *testing.B) {
	msg := benchmarkPostcardMessage{
		Kind:    3,
		Counter: 1 << 32,
		Topic:   "benchmark/topic",
		Data:    []byte("postcard payload used for codec benchmarks"),
	}
	encoded, err := Marshal(msg)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("marshal", func(b *testing.B) {
		b.SetBytes(int64(len(encoded)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := Marshal(msg); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("unmarshal", func(b *testing.B) {
		b.SetBytes(int64(len(encoded)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var got benchmarkPostcardMessage
			if err := Unmarshal(encoded, &got); err != nil {
				b.Fatal(err)
			}
			benchmarkPostcardSink = got
		}
	})
}
