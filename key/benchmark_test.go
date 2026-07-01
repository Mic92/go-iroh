package key

import "testing"

var benchmarkSignatureSink Signature

func BenchmarkSignVerify(b *testing.B) {
	sk, err := GenerateSecretKey()
	if err != nil {
		b.Fatal(err)
	}
	pk := sk.Public()
	msg := []byte("iroh key operation benchmark message")
	sig := sk.Sign(msg)
	b.Run("sign", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchmarkSignatureSink = sk.Sign(msg)
		}
	})
	b.Run("verify", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := pk.Verify(msg, sig); err != nil {
				b.Fatal(err)
			}
		}
	})
}
