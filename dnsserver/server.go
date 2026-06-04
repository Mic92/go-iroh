// Package dnsserver implements an embeddable iroh DNS and pkarr relay server.
package dnsserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/metrics"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxPacketSize = 64 * 1024
	maxPUTSize    = 1024 * 1024
)

// Server stores pkarr relay payloads in memory and serves them over HTTP and
// DNS. It is safe for concurrent use.
type Server struct {
	mu      sync.Mutex
	store   map[string][]byte
	metrics dnsMetrics
}

type dnsMetrics struct {
	httpPuts   atomic.Uint64
	httpGets   atomic.Uint64
	dnsQueries atomic.Uint64
}

// New returns an empty DNS server.
func New() *Server {
	return &Server{store: make(map[string][]byte)}
}

// Snapshot returns the server's counter snapshot for [metrics.Registry].
func (s *Server) Snapshot() metrics.Snapshot {
	return metrics.Snapshot{
		"http_puts":   s.metrics.httpPuts.Load(),
		"http_gets":   s.metrics.httpGets.Load(),
		"dns_queries": s.metrics.dnsQueries.Load(),
	}
}

// ServeHTTP handles PUT and GET of pkarr relay payloads at /pkarr/<key> or
// /<key>.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	keyLabel := strings.TrimPrefix(r.URL.Path, "/")
	keyLabel = strings.TrimPrefix(keyLabel, "pkarr/")
	if keyLabel == "" || strings.Contains(keyLabel, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		s.metrics.httpPuts.Add(1)
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPUTSize))
		if err != nil {
			http.Error(w, "packet too large", http.StatusRequestEntityTooLarge)
			return
		}
		if _, err := packetFromRelayPayload(keyLabel, body); err != nil {
			http.Error(w, "bad signed packet", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.store[keyLabel] = bytes.Clone(body)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		s.metrics.httpGets.Add(1)
		body, ok := s.get(keyLabel)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pkarr-signed-packet")
		w.Write(body)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ServePacketConn serves DNS messages on pc until ctx is canceled or pc returns
// a non-close read error.
func (s *Server) ServePacketConn(ctx context.Context, pc net.PacketConn) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			pc.Close()
		case <-done:
		}
	}()
	defer close(done)

	buf := make([]byte, maxPacketSize)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return err
		}
		req := bytes.Clone(buf[:n])
		go func() {
			resp, err := s.ServeDNSPacket(req)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(resp, addr)
		}()
	}
}

// ServeDNSPacket handles one DNS wire-format message and returns a DNS
// wire-format response.
func (s *Server) ServeDNSPacket(msg []byte) ([]byte, error) {
	s.metrics.dnsQueries.Add(1)
	var p dnsmessage.Parser
	header, err := p.Start(msg)
	if err != nil {
		return nil, fmt.Errorf("dnsserver: parse header: %w", err)
	}
	q, err := p.Question()
	if err != nil {
		return nil, fmt.Errorf("dnsserver: parse question: %w", err)
	}
	txt, ok := s.lookupTXT(q)
	responseHeader := dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: false,
		RCode:              dnsmessage.RCodeSuccess,
	}
	if !ok && q.Type == dnsmessage.TypeTXT {
		responseHeader.RCode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, responseHeader)
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if ok {
		if err := b.TXTResource(dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
			TTL:   30,
		}, dnsmessage.TXTResource{TXT: txt}); err != nil {
			return nil, err
		}
	}
	resp, err := b.Finish()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Server) lookupTXT(q dnsmessage.Question) ([]string, bool) {
	if q.Type != dnsmessage.TypeTXT || q.Class != dnsmessage.ClassINET {
		return nil, false
	}
	keyLabel, ok := keyLabelFromQuery(q.Name.String())
	if !ok {
		return nil, false
	}
	payload, ok := s.get(keyLabel)
	if !ok {
		return nil, false
	}
	packet, err := packetFromRelayPayload(keyLabel, payload)
	if err != nil {
		return nil, false
	}
	txt := packet.TXTRecords(dns.IrohTXTName)
	return txt, len(txt) > 0
}

func (s *Server) get(keyLabel string) ([]byte, bool) {
	s.mu.Lock()
	body, ok := s.store[keyLabel]
	body = bytes.Clone(body)
	s.mu.Unlock()
	return body, ok
}

func packetFromRelayPayload(keyLabel string, payload []byte) (*dns.SignedPacket, error) {
	id, err := key.ParseEndpointIDZ32(keyLabel)
	if err != nil {
		return nil, err
	}
	pubBytes := id.PublicKey().Bytes()
	wire := make([]byte, 0, len(pubBytes)+len(payload))
	wire = append(wire, pubBytes[:]...)
	wire = append(wire, payload...)
	return dns.SignedPacketFromBytes(wire)
}

func keyLabelFromQuery(name string) (string, bool) {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) < 2 || labels[0] != dns.IrohTXTName {
		return "", false
	}
	return labels[1], true
}
