package relayproto

import (
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
)

func FuzzParseRelayFrames(f *testing.F) {
	secret := fuzzSecretKey()
	id := secret.Public().EndpointID()
	challenge := ServerChallenge{Challenge: [16]byte{1, 2, 3}}
	for _, data := range [][]byte{
		(RelayToClientMsg{Type: FramePing, Ping: ping42()}).AppendTo(nil),
		(RelayToClientMsg{Type: FrameStatus, Status: StatusHealthy}).AppendTo(nil),
		(RelayToClientMsg{Type: FrameRestarting, ReconnectIn: time.Millisecond, TryFor: 2 * time.Millisecond}).AppendTo(nil),
		(RelayToClientMsg{Type: FrameRelayToClientDatagram, RemoteEndpointID: id, Datagrams: Datagrams{Contents: []byte("hello")}}).AppendTo(nil),
		(ClientToRelayMsg{Type: FramePong, Ping: ping42()}).AppendTo(nil),
		(ClientToRelayMsg{Type: FrameClientToRelayDatagram, DstEndpointID: id, Datagrams: Datagrams{Contents: []byte("hello")}}).AppendTo(nil),
		challenge.AppendTo(nil),
		NewClientAuth(secret, challenge).AppendTo(nil),
		(ServerConfirmsAuth{}).AppendTo(nil),
		(ServerDeniesAuth{Reason: "no"}).AppendTo(nil),
		{},
	} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseRelayToClientMsg(data, ProtocolV1)
		_, _ = ParseRelayToClientMsg(data, ProtocolV2)
		_, _ = ParseClientToRelayMsg(data)
		_, _ = ParseHandshakeFrame(data)
	})
}

func fuzzSecretKey() key.SecretKey {
	var seed [32]byte
	for i := range seed {
		seed[i] = 42
	}
	return key.NewSecretKey(seed)
}
