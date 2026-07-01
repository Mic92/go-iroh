package relayproto

import (
	"testing"

	"github.com/tmc/go-iroh/key"
)

var benchmarkRelayMsgSink RelayToClientMsg
var benchmarkHandshakeSink any

func BenchmarkRelayFrameEncodeDecode(b *testing.B) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		b.Fatal(err)
	}
	msg := RelayToClientMsg{
		Type:             FrameRelayToClientDatagram,
		RemoteEndpointID: sk.Public().EndpointID(),
		Datagrams:        DatagramsFromBytes(make([]byte, 1200)),
	}
	encoded := msg.AppendTo(make([]byte, 0, msg.EncodedLen()))
	b.Run("encode", func(b *testing.B) {
		buf := make([]byte, 0, msg.EncodedLen())
		b.SetBytes(int64(len(encoded)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf = msg.AppendTo(buf[:0])
		}
	})
	b.Run("decode", func(b *testing.B) {
		b.SetBytes(int64(len(encoded)))
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			got, err := ParseRelayToClientMsg(encoded, ProtocolV2)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkRelayMsgSink = got
		}
	})
}

func BenchmarkRelayHandshake(b *testing.B) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		b.Fatal(err)
	}
	challenge := ServerChallenge{Challenge: [16]byte{0, 1, 2, 3, 5, 8, 13, 21}}
	auth := NewClientAuth(sk, challenge)
	encoded := auth.AppendTo(nil)
	b.Run("sign", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			auth = NewClientAuth(sk, challenge)
		}
	})
	b.Run("verify", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := auth.Verify(challenge); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("parse", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			got, err := ParseHandshakeFrame(encoded)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkHandshakeSink = got
		}
	})
}
