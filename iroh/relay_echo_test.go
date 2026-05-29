package iroh

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tmc/go-iroh/base"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/relay"
)

// echoRelayServer is a hermetic in-process relay server: it speaks
// internal/relayproto over a plain-WS (httptest, no TLS) connection, tracks
// connected clients by endpoint id, forwards client-to-relay datagrams to the
// destination client as relay-to-client datagrams, and answers pings. It is
// enough to carry the QUIC handshake and data between two relay-only endpoints.
type echoRelayServer struct {
	ts *httptest.Server

	mu      sync.Mutex
	clients map[base.EndpointId]*relaySession
}

// relaySession is one connected relay client.
type relaySession struct {
	id   base.EndpointId
	send chan []byte // queued wire frames to write
}

func newEchoRelayServer(t *testing.T) *echoRelayServer {
	t.Helper()
	s := &echoRelayServer{clients: map[base.EndpointId]*relaySession{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", s.handle)
	s.ts = httptest.NewServer(mux)
	t.Cleanup(s.ts.Close)
	return s
}

// url returns the relay URL clients dial.
func (s *echoRelayServer) url(t *testing.T) base.RelayUrl {
	t.Helper()
	u, err := base.ParseRelayUrl(s.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (s *echoRelayServer) register(sess *relaySession) {
	s.mu.Lock()
	s.clients[sess.id] = sess
	s.mu.Unlock()
}

func (s *echoRelayServer) unregister(id base.EndpointId) {
	s.mu.Lock()
	delete(s.clients, id)
	s.mu.Unlock()
}

func (s *echoRelayServer) lookup(id base.EndpointId) (*relaySession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.clients[id]
	return sess, ok
}

func (s *echoRelayServer) handle(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: relayproto.SupportedProtocolVersions(),
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(1024 * 1024)
	ctx := r.Context()
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Handshake: challenge, verify auth, confirm.
	var challenge relayproto.ServerChallenge
	for i := range challenge.Challenge {
		challenge.Challenge[i] = byte(i + 1)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, challenge.AppendTo(nil)); err != nil {
		return
	}
	_, data, err := conn.Read(ctx)
	if err != nil {
		return
	}
	frame, err := relayproto.ParseHandshakeFrame(data)
	if err != nil {
		return
	}
	auth, ok := frame.(*relayproto.ClientAuth)
	if !ok || auth.Verify(challenge) != nil {
		conn.Write(ctx, websocket.MessageBinary, relayproto.ServerDeniesAuth{Reason: "bad auth"}.AppendTo(nil))
		return
	}
	if err := conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil)); err != nil {
		return
	}

	sess := &relaySession{id: auth.PublicKey, send: make(chan []byte, 256)}
	s.register(sess)
	defer s.unregister(sess.id)

	// Writer goroutine: drains the session's send queue to the socket.
	writerCtx, writerCancel := context.WithCancel(ctx)
	defer writerCancel()
	go func() {
		for {
			select {
			case <-writerCtx.Done():
				return
			case b := <-sess.send:
				if conn.Write(writerCtx, websocket.MessageBinary, b) != nil {
					return
				}
			}
		}
	}()

	// Read loop: forward datagrams, answer pings.
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		msg, err := relayproto.ParseClientToRelayMsg(data)
		if err != nil {
			return
		}
		switch msg.Type {
		case relayproto.FrameClientToRelayDatagram, relayproto.FrameClientToRelayDatagramBat:
			dst, ok := s.lookup(msg.DstEndpointId)
			if !ok {
				continue
			}
			fwd := relayproto.RelayToClientMsg{
				Type:             relayproto.FrameRelayToClientDatagram,
				RemoteEndpointId: sess.id,
				Datagrams:        msg.Datagrams,
			}
			select {
			case dst.send <- fwd.AppendTo(nil):
			default:
			}
		case relayproto.FramePing:
			pong := relayproto.RelayToClientMsg{Type: relayproto.FramePong, Ping: msg.Ping}
			select {
			case sess.send <- pong.AppendTo(nil):
			default:
			}
		}
	}
}

// TestRelayOnlyEcho is the slice-D integration gate: two endpoints with no
// direct-IP address connect entirely through an in-process relay, exchange a
// bidi-stream echo and a datagram, and each observes the other's verified
// endpoint id.
func TestRelayOnlyEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv := newEchoRelayServer(t)
	relayURL := srv.url(t)
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))

	const alpn = "iroh-relay-echo/0"

	srvKey, _ := base.GenerateSecretKey()
	server, err := Bind(ctx,
		WithSecretKey(srvKey),
		WithALPNs([]byte(alpn)),
		WithRelayMode(mode),
		// Bind to loopback so no usable public IP is advertised; the addr we
		// dial carries only the relay URL, so the path is relay-only.
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)

	client, err := Bind(ctx, WithRelayMode(mode))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	// Wait for both endpoints to connect to the relay so the relay can route
	// the QUIC handshake between them.
	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}
	if err := client.Online(ctx); err != nil {
		t.Fatalf("client online: %v", err)
	}

	type srvResult struct {
		peer base.EndpointId
		err  error
	}
	done := make(chan srvResult, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			done <- srvResult{err: err}
			return
		}
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- srvResult{err: err}
			return
		}
		b, _ := io.ReadAll(s)
		s.Write(b)
		s.Close()
		dg, err := conn.ReadDatagram(ctx)
		if err == nil {
			conn.SendDatagram(dg)
		}
		done <- srvResult{peer: conn.RemoteID()}
	}()

	// Relay-only address: id + relay URL, no direct IP.
	addr := base.NewEndpointAddr(server.ID()).WithRelayURL(relayURL)

	conn, err := client.Connect(ctx, addr, []byte(alpn))
	if err != nil {
		t.Fatalf("relay connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if !conn.RemoteID().Equal(server.ID()) {
		t.Errorf("client saw server id %s, want %s", conn.RemoteID(), server.ID())
	}

	s, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const msg = "hello over relay"
	s.Write([]byte(msg))
	s.Close()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != msg {
		t.Errorf("stream echo = %q, want %q", got, msg)
	}

	const dmsg = "relay-dgram"
	if err := conn.SendDatagram([]byte(dmsg)); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	dg, err := conn.ReadDatagram(ctx)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	if string(dg) != dmsg {
		t.Errorf("datagram echo = %q, want %q", dg, dmsg)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	if !res.peer.Equal(client.ID()) {
		t.Errorf("server saw client id %s, want %s", res.peer, client.ID())
	}
}
