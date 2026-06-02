package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// DoTLookuper resolves TXT records using DNS-over-TLS.
//
// Address is a host:port pair. TLSConfig may be nil to use the default TLS
// configuration.
type DoTLookuper struct {
	Address   string
	TLSConfig *tls.Config
	Dialer    *net.Dialer
}

// LookupTXT resolves name as TXT using DNS-over-TLS.
func (l *DoTLookuper) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if l == nil || l.Address == "" {
		return nil, fmt.Errorf("dot: missing server address")
	}
	msg, err := packTXTQuery(name)
	if err != nil {
		return nil, err
	}
	dialer := l.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: DNSTimeout}
	}
	cfg := l.TLSConfig
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", l.Address, cfg)
	if err != nil {
		return nil, fmt.Errorf("dot lookup %q: dial: %w", name, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(DNSTimeout))
	}
	if err := writeDNSMessage(conn, msg); err != nil {
		return nil, fmt.Errorf("dot lookup %q: write query: %w", name, err)
	}
	body, err := readDNSMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("dot lookup %q: read response: %w", name, err)
	}
	txt, err := unpackTXTResponse(body)
	if err != nil {
		return nil, fmt.Errorf("dot lookup %q: %w", name, err)
	}
	return txt, nil
}

func writeDNSMessage(w io.Writer, msg []byte) error {
	if len(msg) > 0xffff {
		return fmt.Errorf("dns message too large: %d bytes", len(msg))
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(msg)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

func readDNSMessage(r io.Reader) ([]byte, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(prefix[:])
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
