package relayclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// fakeRelay is a minimal in-process relay server speaking enough of the protocol
// to test the client: it accepts the WS upgrade, sends a challenge, verifies the
// client's auth, confirms, then echoes one datagram back as a relay-to-client
// datagram.
func fakeRelay(t *testing.T, deny bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: relayproto.SupportedProtocolVersions(),
		})
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		defer conn.Close(websocket.StatusNormalClosure, "")

		// Send challenge.
		var challenge relayproto.ServerChallenge
		for i := range challenge.Challenge {
			challenge.Challenge[i] = byte(i + 1)
		}
		if err := conn.Write(ctx, websocket.MessageBinary, challenge.AppendTo(nil)); err != nil {
			return
		}

		// Read client auth.
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		frame, err := relayproto.ParseHandshakeFrame(data)
		if err != nil {
			t.Errorf("parse client auth: %v", err)
			return
		}
		auth, ok := frame.(*relayproto.ClientAuth)
		if !ok {
			t.Errorf("expected ClientAuth, got %T", frame)
			return
		}
		if err := auth.Verify(challenge); err != nil {
			t.Errorf("client auth verify: %v", err)
			return
		}

		if deny {
			conn.Write(ctx, websocket.MessageBinary, relayproto.ServerDeniesAuth{Reason: "nope"}.AppendTo(nil))
			return
		}
		// Confirm.
		if err := conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil)); err != nil {
			return
		}

		// Echo loop: turn a client datagram into a relay-to-client datagram.
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			msg, err := relayproto.ParseClientToRelayMsg(data)
			if err != nil {
				return
			}
			if msg.Type == relayproto.FrameClientToRelayDatagram || msg.Type == relayproto.FrameClientToRelayDatagramBat {
				reply := relayproto.RelayToClientMsg{
					Type:             relayproto.FrameRelayToClientDatagram,
					RemoteEndpointID: msg.DstEndpointID,
					Datagrams:        msg.Datagrams,
				}
				conn.Write(ctx, websocket.MessageBinary, reply.AppendTo(nil))
			}
		}
	})
	return httptest.NewServer(mux)
}

func relayURL(t *testing.T, ts *httptest.Server) netaddr.RelayURL {
	t.Helper()
	u, err := netaddr.ParseRelayURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestClientConnectAndEcho(t *testing.T) {
	ts := fakeRelay(t, false)
	defer ts.Close()

	sk, _ := key.GenerateSecretKey()
	ctx := context.Background()
	c, err := Connect(ctx, relayURL(t, ts), Options{SecretKey: sk})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	// Send a datagram destined for some peer.
	dst, _ := key.GenerateSecretKey()
	payload := []byte("hello relay")
	err = c.Send(ctx, relayproto.ClientToRelayMsg{
		Type:          relayproto.FrameClientToRelayDatagram,
		DstEndpointID: dst.Public().EndpointID(),
		Datagrams:     relayproto.DatagramsFromBytes(payload),
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	msg, err := c.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if msg.Type != relayproto.FrameRelayToClientDatagram {
		t.Fatalf("got frame %s, want RelayToClientDatagram", msg.Type)
	}
	if string(msg.Datagrams.Contents) != string(payload) {
		t.Errorf("echo = %q, want %q", msg.Datagrams.Contents, payload)
	}
	if !msg.RemoteEndpointID.Equal(dst.Public().EndpointID()) {
		t.Error("remote endpoint id mismatch")
	}
}

func TestClientHandshakeDenied(t *testing.T) {
	ts := fakeRelay(t, true)
	defer ts.Close()

	sk, _ := key.GenerateSecretKey()
	_, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if err == nil {
		t.Fatal("expected handshake denial error")
	}
	if !strings.Contains(err.Error(), "denied") && !strings.Contains(err.Error(), "nope") {
		t.Errorf("error = %v, want denial", err)
	}
}

func TestWebsocketURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://relay.example.com", "wss://relay.example.com/relay"},
		{"http://localhost:8080", "ws://localhost:8080/relay"},
	}
	for _, c := range cases {
		u, err := netaddr.ParseRelayURL(c.in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := websocketURL(u)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("websocketURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
