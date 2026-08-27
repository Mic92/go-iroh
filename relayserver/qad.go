package relayserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	itls "github.com/tmc/go-iroh/internal/itls/tls"
	quic "github.com/tmc/go-iroh/internal/qng"
)

// alpnQAD is iroh-relay's ALPN_QUIC_ADDR_DISC.
const alpnQAD = "/iroh-qad/0"

// ServeQAD runs QUIC address discovery on conn until ctx is cancelled, so
// clients behind NAT learn their public UDP address. tlsConf supplies the
// certificate, which clients verify against the relay hostname.
func (s *Server) ServeQAD(ctx context.Context, conn net.PacketConn, tlsConf *tls.Config) error {
	if tlsConf == nil || (len(tlsConf.Certificates) == 0 && tlsConf.GetCertificate == nil) {
		return errors.New("relayserver: QAD requires a TLS certificate")
	}
	tr := &quic.Transport{Conn: conn}
	defer tr.Close()
	ln, err := tr.Listen(qadServerTLS(tlsConf), &quic.Config{
		SendObservedAddressReports: true,
		MaxIdleTimeout:             35 * time.Second,
	})
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		// The observed address is sent with the handshake; the client closes.
		if _, err := ln.Accept(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.metrics.qadConnections.Add(1)
	}
}

// qadServerTLS adapts the config to the forked TLS stack qng uses.
func qadServerTLS(c *tls.Config) *itls.Config {
	out := &itls.Config{
		MinVersion: itls.VersionTLS13,
		NextProtos: []string{alpnQAD},
	}
	for i := range c.Certificates {
		out.Certificates = append(out.Certificates, itlsCert(&c.Certificates[i]))
	}
	if c.GetCertificate != nil {
		out.GetCertificate = func(h *itls.ClientHelloInfo) (*itls.Certificate, error) {
			cert, err := c.GetCertificate(&tls.ClientHelloInfo{
				ServerName:      h.ServerName,
				SupportedProtos: h.SupportedProtos,
				CipherSuites:    h.CipherSuites,
				Conn:            h.Conn,
			})
			if err != nil || cert == nil {
				return nil, err
			}
			ic := itlsCert(cert)
			return &ic, nil
		}
	}
	return out
}

func itlsCert(c *tls.Certificate) itls.Certificate {
	return itls.Certificate{Certificate: c.Certificate, PrivateKey: c.PrivateKey, Leaf: c.Leaf}
}
