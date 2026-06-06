package iroh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// TCPStreamTransport is a TCP-backed [StreamTransport].
//
// It is suitable for loopback, ordinary LAN, Thunderbolt Bridge IP, or an
// explicitly selected AWDL address. It does not enumerate interfaces or activate
// platform transports.
type TCPStreamTransport struct {
	id    uint64
	ln    net.Listener
	addr  netaddr.CustomAddr
	link  TransportLinkClass
	close sync.Once
}

// ListenTCPStreamTransport listens on bind and returns a stream transport.
func ListenTCPStreamTransport(id uint64, bind string, link TransportLinkClass) (*TCPStreamTransport, error) {
	if id == 0 {
		return nil, errors.New("iroh: zero tcp stream transport id")
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, fmt.Errorf("iroh: listen tcp stream transport: %w", err)
	}
	return &TCPStreamTransport{
		id:   id,
		ln:   ln,
		addr: netaddr.NewCustomAddr(id, []byte(ln.Addr().String())),
		link: link,
	}, nil
}

func (t *TCPStreamTransport) ID() uint64 { return t.id }

func (t *TCPStreamTransport) LinkClass() TransportLinkClass { return t.link }

func (t *TCPStreamTransport) LocalAddrs(ctx context.Context) ([]netaddr.CustomAddr, error) {
	_ = ctx
	return []netaddr.CustomAddr{t.addr}, nil
}

func (t *TCPStreamTransport) DialStream(ctx context.Context, remote netaddr.CustomAddr, opts StreamOptions) (net.Conn, error) {
	if remote.ID() != t.id {
		return nil, fmt.Errorf("iroh: tcp stream transport id %d, want %d", remote.ID(), t.id)
	}
	addr := string(remote.Data())
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("iroh: dial tcp stream transport: %w", err)
	}
	if err := writeStreamOpenToken(c, opts.Token); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (t *TCPStreamTransport) ListenStreams(ctx context.Context, accept func(StreamAccept) error) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			t.ln.Close()
		case <-done:
		}
	}()
	defer close(done)
	for {
		c, err := t.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("iroh: accept tcp stream transport: %w", err)
		}
		tok, err := readStreamOpenToken(c)
		if err != nil {
			c.Close()
			return err
		}
		if err := accept(StreamAccept{Conn: c, Token: tok}); err != nil {
			c.Close()
			return err
		}
	}
}

func (t *TCPStreamTransport) Close() error {
	var err error
	t.close.Do(func() {
		err = t.ln.Close()
	})
	return err
}

func writeStreamOpenToken(w io.Writer, tok StreamOpenToken) error {
	var b []byte
	b = append(b, streamOpenTokenVersion)
	var err error
	if b, err = appendStreamTokenString(b, tok.LocalID); err != nil {
		return err
	}
	if b, err = appendStreamTokenString(b, tok.RemoteID); err != nil {
		return err
	}
	if b, err = appendStreamTokenString(b, tok.ALPN); err != nil {
		return err
	}
	b = binary.BigEndian.AppendUint64(b, tok.StableID)
	b = binary.BigEndian.AppendUint64(b, tok.TransportID)
	if b, err = appendStreamTokenString(b, tok.Purpose); err != nil {
		return err
	}
	if b, err = appendStreamTokenString(b, tok.Nonce); err != nil {
		return err
	}
	b = binary.BigEndian.AppendUint64(b, uint64(tok.Expiry.UnixNano()))
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("iroh: write stream token: %w", err)
	}
	return nil
}

func readStreamOpenToken(r io.Reader) (StreamOpenToken, error) {
	p := streamTokenParser{r: r}
	if p.byte() != streamOpenTokenVersion {
		return StreamOpenToken{}, errors.New("iroh: stream token version mismatch")
	}
	tok := StreamOpenToken{
		LocalID:  p.string(),
		RemoteID: p.string(),
		ALPN:     p.string(),
	}
	tok.StableID = p.u64()
	tok.TransportID = p.u64()
	tok.Purpose = p.string()
	tok.Nonce = p.string()
	tok.Expiry = time.Unix(0, int64(p.u64()))
	if p.err != nil {
		return StreamOpenToken{}, fmt.Errorf("iroh: read stream token: %w", p.err)
	}
	return tok, nil
}

const (
	streamOpenTokenVersion = 1
)

var errStreamTokenStringTooLong = errors.New("iroh: stream token string too long")

func appendStreamTokenString(b []byte, s string) ([]byte, error) {
	if len(s) > 0xffff {
		return nil, errStreamTokenStringTooLong
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...), nil
}

type streamTokenParser struct {
	r   io.Reader
	err error
}

func (p *streamTokenParser) byte() byte {
	if p.err != nil {
		return 0
	}
	var b [1]byte
	if _, err := io.ReadFull(p.r, b[:]); err != nil {
		p.err = err
		return 0
	}
	return b[0]
}

func (p *streamTokenParser) u16() uint16 {
	if p.err != nil {
		return 0
	}
	var b [2]byte
	if _, err := io.ReadFull(p.r, b[:]); err != nil {
		p.err = err
		return 0
	}
	return binary.BigEndian.Uint16(b[:])
}

func (p *streamTokenParser) u64() uint64 {
	if p.err != nil {
		return 0
	}
	var b [8]byte
	if _, err := io.ReadFull(p.r, b[:]); err != nil {
		p.err = err
		return 0
	}
	return binary.BigEndian.Uint64(b[:])
}

func (p *streamTokenParser) string() string {
	n := int(p.u16())
	if p.err != nil {
		return ""
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(p.r, b); err != nil {
		p.err = err
		return ""
	}
	return string(b)
}
