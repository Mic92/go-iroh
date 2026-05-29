// RFC 7250 raw public key support for TLS 1.3.
//
// This file adds the negotiation glue and certificate handling for the
// client_certificate_type / server_certificate_type extensions. The wire-level
// extension marshaling lives in handshake_messages.go; the per-message
// negotiation hooks call into the helpers here. When raw public keys are
// negotiated, the Certificate message carries a bare SubjectPublicKeyInfo
// instead of an X.509 chain.
//
// This is the addition that makes the vendored crypto/tls wire-compatible with
// iroh's raw-public-key P2P handshake; it is not present in upstream crypto/tls.

package tls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"time"
)

// RawPublicKeys, when set on a [Config], makes the connection use RFC 7250 raw
// public keys for both the local certificate and peer verification (TLS 1.3
// only, mutual). The local [Config.Certificates] entry's leaf bytes must be a
// DER SubjectPublicKeyInfo (see [MarshalRawPublicKeyCertificate]); peer
// verification is delegated to [Config.VerifyConnection], where the peer's
// public key is available as ConnectionState.PeerCertificates[0].PublicKey.
//
// Session resumption must be disabled (Config.SessionTicketsDisabled) when this
// is set, because resumed handshakes skip the Certificate message and cannot
// renegotiate the certificate type.
type rawPublicKeysConfig struct {
	enabled bool
}

// rawPublicKeysEnabled reports whether c opts into RFC 7250 raw public keys.
func (c *Config) rawPublicKeysEnabled() bool {
	return c != nil && c.RawPublicKeys
}

// MarshalRawPublicKeyCertificate returns a [Certificate] suitable for a raw
// public key handshake: its single leaf entry is the DER SubjectPublicKeyInfo of
// pub, and priv is the matching private key. pub/priv must be an ed25519 key for
// iroh compatibility, though any key type x509.MarshalPKIXPublicKey supports
// works.
func MarshalRawPublicKeyCertificate(pub any, priv any) (Certificate, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Certificate{}, err
	}
	return Certificate{Certificate: [][]byte{spki}, PrivateKey: priv}, nil
}

// parseRawPublicKeyCert parses a DER SubjectPublicKeyInfo into a synthetic
// *x509.Certificate carrying only the PublicKey and PublicKeyAlgorithm, so the
// existing CertificateVerify path (which reads peerCertificates[0].PublicKey)
// works unchanged.
func parseRawPublicKeyCert(spki []byte) (*x509.Certificate, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{
		// Raw mirrors RawSubjectPublicKeyInfo so the cert survives the session-ticket
		// round trip: SessionState.Bytes serializes peer certificates by their Raw
		// bytes (ticket.go certificatesToBytesSlice). A raw-key "certificate" has no
		// DER body of its own, so we carry the SPKI; parseSessionStateCertificate
		// reads it back with parseRawPublicKeyCert when x509.ParseCertificate fails.
		Raw:                     spki,
		RawSubjectPublicKeyInfo: spki,
		PublicKey:               pub,
		PublicKeyAlgorithm:      publicKeyAlgorithmFor(pub),
		// RFC 7250 raw public keys carry no validity period: the SubjectPublicKeyInfo
		// has no NotBefore/NotAfter, and none is sent on the wire. The TLS session
		// resumption logic (handshake_client.go loadSession, handshake_server_tls13.go
		// checkForResumption) nonetheless guards on peerCertificates[0].NotAfter, so an
		// unbounded window keeps cached raw-key sessions valid for 0-RTT instead of
		// being discarded as expired. These fields are purely local and never serialized.
		NotBefore: time.Unix(0, 0),
		NotAfter:  time.Unix(1<<62, 0),
	}
	return cert, nil
}

// parseSessionStateCertificate reconstructs a peer certificate stored in a TLS
// 1.3 session ticket (see [ParseSessionState]). Tickets serialize each peer
// certificate by its Raw bytes; for an X.509 chain those are a DER certificate,
// but for an RFC 7250 raw public key they are a bare SubjectPublicKeyInfo, which
// x509.ParseCertificate cannot decode. When the normal parse fails, fall back to
// parseRawPublicKeyCert so resumption and 0-RTT work for raw-key peers. The two
// encodings are unambiguous: an SPKI is never a valid certificate and vice
// versa, so the fallback only triggers for genuine raw keys.
func parseSessionStateCertificate(der []byte) (*x509.Certificate, error) {
	c, err := globalCertCache.newCert(der)
	if err == nil {
		return c, nil
	}
	raw, rawErr := parseRawPublicKeyCert(der)
	if rawErr != nil {
		// Surface the original X.509 error; the raw-key fallback is best-effort.
		return nil, err
	}
	return raw, nil
}

// publicKeyAlgorithmFor maps a parsed public key to its x509.PublicKeyAlgorithm.
func publicKeyAlgorithmFor(pub any) x509.PublicKeyAlgorithm {
	switch pub.(type) {
	case ed25519.PublicKey:
		return x509.Ed25519
	case *ecdsa.PublicKey:
		return x509.ECDSA
	case *rsa.PublicKey:
		return x509.RSA
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

// verifyServerRawPublicKey handles the client-side verification of a server that
// presented a raw public key (RFC 7250). The peer's public key is exposed via
// ConnectionState.PeerCertificates[0].PublicKey for the application's
// VerifyConnection callback (which performs the iroh endpoint-id check); there is
// no X.509 chain to validate.
func (c *Conn) verifyServerRawPublicKey(certificates [][]byte) error {
	if len(certificates) != 1 {
		c.sendAlert(alertBadCertificate)
		return errors.New("tls: raw public key handshake requires exactly one certificate entry")
	}
	cert, err := parseRawPublicKeyCert(certificates[0])
	if err != nil {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: failed to parse server raw public key: " + err.Error())
	}
	c.peerCertificates = []*x509.Certificate{cert}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, nil); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}
	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}
	return nil
}
