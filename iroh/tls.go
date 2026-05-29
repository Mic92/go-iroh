package iroh

import (
	"crypto/ed25519"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/tmc/go-iroh/base"
	tls "github.com/tmc/go-iroh/internal/itls/tls"
)

// alpn values and TLS parameters shared by iroh peers. iroh authenticates peers
// with TLS 1.3 raw public keys (RFC 7250): each endpoint presents its ed25519
// public key as a bare SubjectPublicKeyInfo, and verifies the peer's key rather
// than any X.509 chain. See [github.com/tmc/go-iroh/internal/itls/tls] for the
// raw-public-key TLS implementation.

// base32DNSSEC is data_encoding::BASE32_DNSSEC: RFC 4648 base32hex, lowercase,
// unpadded. iroh encodes an EndpointId into the TLS server name with it (see
// [ServerName]); it differs from the z-base-32 used for human-facing key
// strings.
var base32DNSSEC = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding(base32.NoPadding)

// tlsNameSuffix is appended to the base32 endpoint id to form the TLS server
// name. The .invalid TLD (RFC 2606) never resolves; the iroh label is a
// protocol marker.
const tlsNameSuffix = ".iroh.invalid"

// ServerName returns the TLS server name (SNI) iroh uses to address id:
// BASE32_DNSSEC(id) + ".iroh.invalid". A dialing endpoint puts this in its
// ClientHello; the accepting endpoint proves it holds id by presenting id as
// its raw public key. Deriving the name from the id (rather than a constant)
// also keeps per-peer 0-RTT session tickets in separate cache buckets.
func ServerName(id base.EndpointId) string {
	b := id.Bytes()
	return base32DNSSEC.EncodeToString(b[:]) + tlsNameSuffix
}

// endpointIdFromServerName is the inverse of [ServerName]. It reports whether
// name is a well-formed iroh server name and, if so, the encoded endpoint id.
func endpointIdFromServerName(name string) (base.EndpointId, bool) {
	rest, ok := strings.CutSuffix(name, tlsNameSuffix)
	if !ok || strings.Contains(rest, ".") {
		return base.EndpointId{}, false
	}
	raw, err := base32DNSSEC.DecodeString(rest)
	if err != nil || len(raw) != base.PublicKeyLength {
		return base.EndpointId{}, false
	}
	id, err := base.PublicKeyFromSlice(raw)
	if err != nil {
		return base.EndpointId{}, false
	}
	return id, true
}

// rawKeyCertificate builds the RFC 7250 certificate for sk: the leaf is sk's
// ed25519 public key as a SubjectPublicKeyInfo, signed under sk during the
// handshake.
func rawKeyCertificate(sk base.SecretKey) (tls.Certificate, error) {
	seed := sk.Bytes()
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return tls.MarshalRawPublicKeyCertificate(pub, priv)
}

// peerEndpointId extracts the peer's endpoint id from a completed raw-public-key
// TLS handshake. It is the public key carried in the single peer certificate.
func peerEndpointId(cs tls.ConnectionState) (base.EndpointId, error) {
	if len(cs.PeerCertificates) != 1 {
		return base.EndpointId{}, fmt.Errorf("iroh: expected exactly one peer certificate, got %d", len(cs.PeerCertificates))
	}
	pub, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return base.EndpointId{}, errors.New("iroh: peer key is not ed25519")
	}
	id, err := base.PublicKeyFromSlice(pub)
	if err != nil {
		return base.EndpointId{}, fmt.Errorf("iroh: peer key: %w", err)
	}
	return id, nil
}

// clientTLSConfig builds the TLS configuration a dialing endpoint uses to
// connect to want. It presents sk as a raw public key and verifies that the
// peer's key equals want — the same check iroh's ServerCertificateVerifier
// performs by decoding the dialed server name (RFC 7250 server auth).
func clientTLSConfig(sk base.SecretKey, want base.EndpointId, alpns []string) (*tls.Config, error) {
	cert, err := rawKeyCertificate(sk)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:           []tls.Certificate{cert},
		RawPublicKeys:          true,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		NextProtos:             alpns,
		ServerName:             ServerName(want),
		InsecureSkipVerify:     true, // chain verification is replaced by VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			got, err := peerEndpointId(cs)
			if err != nil {
				return err
			}
			if !got.Equal(want) {
				return fmt.Errorf("iroh: server identity mismatch: dialed %s, got %s", want, got)
			}
			return nil
		},
	}, nil
}

// serverTLSConfig builds the TLS configuration an accepting endpoint uses. It
// presents sk as a raw public key and requires the client to do the same; the
// client's identity is learned from its certificate after the handshake (iroh's
// server does not check the client key against anything, mirroring
// ClientCertificateVerifier).
func serverTLSConfig(sk base.SecretKey, alpns []string) (*tls.Config, error) {
	cert, err := rawKeyCertificate(sk)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:           []tls.Certificate{cert},
		RawPublicKeys:          true,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		NextProtos:             alpns,
		ClientAuth:             tls.RequireAnyClientCert,
		InsecureSkipVerify:     true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			// Authenticate that a client key is present and parseable; the
			// signature over the handshake transcript proves possession. The
			// concrete identity is surfaced to the application post-handshake.
			_, err := peerEndpointId(cs)
			return err
		},
	}, nil
}
