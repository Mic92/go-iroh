// Package relayserver implements the server side of the iroh relay protocol.
//
// It accepts relay WebSocket clients, authenticates them with the relay
// challenge protocol, and forwards relay datagrams between connected endpoint
// ids. It is intentionally small: persistence, metrics, access control, and
// clustering belong above this package.
package relayserver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/metrics"
)

const (
	relayPath    = "/relay"
	maxFrameSize = 1024 * 1024
)

// Server is an iroh relay protocol HTTP handler.
type Server struct {
	mu      sync.Mutex
	clients map[key.EndpointID]*session
	metrics relayMetrics
}

type relayMetrics struct {
	clientsAccepted    atomic.Uint64
	pings              atomic.Uint64
	datagramsForwarded atomic.Uint64
}

// New returns a relay server.
func New() *Server {
	return &Server{clients: make(map[key.EndpointID]*session)}
}

// Snapshot returns the server's counter snapshot for [metrics.Registry].
func (s *Server) Snapshot() metrics.Snapshot {
	return metrics.Snapshot{
		"clients_accepted":    s.metrics.clientsAccepted.Load(),
		"pings":               s.metrics.pings.Load(),
		"datagrams_forwarded": s.metrics.datagramsForwarded.Load(),
	}
}

// ServeHTTP handles relay WebSocket requests at /relay.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != relayPath {
		http.NotFound(w, r)
		return
	}
	s.handleRelay(w, r)
}

type session struct {
	id      key.EndpointID
	version relayproto.ProtocolVersion
	send    chan []byte
}

func (s *Server) handleRelay(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: relayproto.SupportedProtocolVersions(),
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(maxFrameSize)
	ctx := r.Context()
	defer conn.Close(websocket.StatusNormalClosure, "")

	version, ok := relayproto.ParseProtocolVersion(conn.Subprotocol())
	if !ok {
		conn.Close(websocket.StatusProtocolError, "bad relay protocol")
		return
	}

	id, err := authenticate(ctx, conn, r.TLS, r.Header.Get(relayproto.ClientAuthHeader))
	if err != nil {
		return
	}
	s.metrics.clientsAccepted.Add(1)

	sess := &session{
		id:      id,
		version: version,
		send:    make(chan []byte, relayproto.PerClientSendQueueDepth),
	}
	if old := s.register(sess); old != nil {
		old.enqueue(relayproto.RelayToClientMsg{
			Type:   relayproto.FrameStatus,
			Status: relayproto.StatusSameEndpointIDConnected,
		})
	}
	defer s.unregister(sess)

	writerCtx, writerCancel := context.WithCancel(ctx)
	defer writerCancel()
	go writeLoop(writerCtx, conn, sess)

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		msg, err := relayproto.ParseClientToRelayMsg(data)
		if err != nil {
			conn.Close(websocket.StatusProtocolError, "bad relay frame")
			return
		}
		s.handleClientMsg(sess, msg)
	}
}

func authenticate(ctx context.Context, conn *websocket.Conn, state *tls.ConnectionState, clientAuthHeader string) (key.EndpointID, error) {
	if clientAuthHeader != "" {
		auth, err := relayproto.KeyMaterialClientAuthFromHeader(clientAuthHeader)
		if err == nil && auth.Verify(state) == nil {
			if err := conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil)); err != nil {
				return key.EndpointID{}, err
			}
			return auth.PublicKey.EndpointID(), nil
		}
	}

	var challenge relayproto.ServerChallenge
	if _, err := rand.Read(challenge.Challenge[:]); err != nil {
		return key.EndpointID{}, err
	}
	if err := conn.Write(ctx, websocket.MessageBinary, challenge.AppendTo(nil)); err != nil {
		return key.EndpointID{}, err
	}
	_, data, err := conn.Read(ctx)
	if err != nil {
		return key.EndpointID{}, err
	}
	frame, err := relayproto.ParseHandshakeFrame(data)
	if err != nil {
		return key.EndpointID{}, err
	}
	auth, ok := frame.(*relayproto.ClientAuth)
	if !ok {
		deny(ctx, conn, "expected client auth")
		return key.EndpointID{}, errors.New("relayserver: expected client auth")
	}
	if err := auth.Verify(challenge); err != nil {
		deny(ctx, conn, "bad auth")
		return key.EndpointID{}, err
	}
	if err := conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil)); err != nil {
		return key.EndpointID{}, err
	}
	return auth.PublicKey.EndpointID(), nil
}

func deny(ctx context.Context, conn *websocket.Conn, reason string) {
	_ = conn.Write(ctx, websocket.MessageBinary, relayproto.ServerDeniesAuth{Reason: reason}.AppendTo(nil))
}

func writeLoop(ctx context.Context, conn *websocket.Conn, sess *session) {
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-sess.send:
			if conn.Write(ctx, websocket.MessageBinary, b) != nil {
				return
			}
		}
	}
}

func (s *Server) handleClientMsg(src *session, msg relayproto.ClientToRelayMsg) {
	switch msg.Type {
	case relayproto.FrameClientToRelayDatagram, relayproto.FrameClientToRelayDatagramBat:
		dst := s.lookup(msg.DstEndpointID)
		if dst == nil {
			return
		}
		s.metrics.datagramsForwarded.Add(1)
		dst.enqueue(relayproto.RelayToClientMsg{
			Type:             relayproto.FrameRelayToClientDatagram,
			RemoteEndpointID: src.id,
			Datagrams:        msg.Datagrams,
		})
	case relayproto.FramePing:
		s.metrics.pings.Add(1)
		src.enqueue(relayproto.RelayToClientMsg{Type: relayproto.FramePong, Ping: msg.Ping})
	}
}

func (s *Server) register(sess *session) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.clients[sess.id]
	s.clients[sess.id] = sess
	return old
}

func (s *Server) unregister(sess *session) {
	s.mu.Lock()
	if s.clients[sess.id] == sess {
		delete(s.clients, sess.id)
	}
	for _, peer := range s.clients {
		peer.enqueue(relayproto.RelayToClientMsg{
			Type:         relayproto.FrameEndpointGone,
			EndpointGone: sess.id,
		})
	}
	s.mu.Unlock()
}

func (s *Server) lookup(id key.EndpointID) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clients[id]
}

func (s *session) enqueue(msg relayproto.RelayToClientMsg) {
	select {
	case s.send <- msg.AppendTo(nil):
	default:
	}
}
