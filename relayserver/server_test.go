package relayserver

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/relayclient"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestRelayServerForwardsDatagramAndPong(t *testing.T) {
	srv := New()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	u, err := netaddr.ParseRelayURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sk1, _ := key.GenerateSecretKey()
	c1, err := relayclient.Connect(ctx, u, relayclient.Options{SecretKey: sk1})
	if err != nil {
		t.Fatalf("connect c1: %v", err)
	}
	defer c1.Close()

	sk2, _ := key.GenerateSecretKey()
	c2, err := relayclient.Connect(ctx, u, relayclient.Options{SecretKey: sk2})
	if err != nil {
		t.Fatalf("connect c2: %v", err)
	}
	defer c2.Close()

	var ping [8]byte
	copy(ping[:], "pingpong")
	if err := c1.Send(ctx, relayproto.ClientToRelayMsg{Type: relayproto.FramePing, Ping: ping}); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	pong, err := c1.Recv(ctx)
	if err != nil {
		t.Fatalf("recv pong: %v", err)
	}
	if pong.Type != relayproto.FramePong || pong.Ping != ping {
		t.Fatalf("pong = %+v, want ping echo", pong)
	}

	payload := []byte("hello relay")
	if err := c1.Send(ctx, relayproto.ClientToRelayMsg{
		Type:          relayproto.FrameClientToRelayDatagram,
		DstEndpointID: sk2.Public().EndpointID(),
		Datagrams:     relayproto.DatagramsFromBytes(payload),
	}); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	got, err := c2.Recv(ctx)
	if err != nil {
		t.Fatalf("recv forwarded datagram: %v", err)
	}
	if got.Type != relayproto.FrameRelayToClientDatagram {
		t.Fatalf("type = %v, want datagram", got.Type)
	}
	if !got.RemoteEndpointID.Equal(sk1.Public().EndpointID()) {
		t.Fatalf("remote id = %s, want %s", got.RemoteEndpointID, sk1.Public().EndpointID())
	}
	if string(got.Datagrams.Contents) != string(payload) {
		t.Fatalf("datagram = %q, want %q", got.Datagrams.Contents, payload)
	}

	snapshot := srv.Snapshot()
	if snapshot["clients_accepted"] != 2 || snapshot["pings"] != 1 || snapshot["datagrams_forwarded"] != 1 {
		t.Fatalf("Snapshot = %+v, want clients=2 pings=1 datagrams=1", snapshot)
	}
}
