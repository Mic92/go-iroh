package handshake

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	tls "github.com/tmc/go-iroh/internal/itls/tls"

	"golang.org/x/crypto/chacha20poly1305"
)

// These cipher suite implementations are copied from the standard library crypto/tls package.

const aeadNonceLength = 12

type cipherSuite struct {
	ID     uint16
	Hash   crypto.Hash
	KeyLen int
	AEAD   func(key, nonceMask []byte) *xorNonceAEAD
}

func (s cipherSuite) IVLen() int { return aeadNonceLength }

func getCipherSuite(id uint16) cipherSuite {
	switch id {
	case tls.TLS_AES_128_GCM_SHA256:
		return cipherSuite{ID: tls.TLS_AES_128_GCM_SHA256, Hash: crypto.SHA256, KeyLen: 16, AEAD: aeadAESGCMTLS13}
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return cipherSuite{ID: tls.TLS_CHACHA20_POLY1305_SHA256, Hash: crypto.SHA256, KeyLen: 32, AEAD: aeadChaCha20Poly1305}
	case tls.TLS_AES_256_GCM_SHA384:
		return cipherSuite{ID: tls.TLS_AES_256_GCM_SHA384, Hash: crypto.SHA384, KeyLen: 32, AEAD: aeadAESGCMTLS13}
	default:
		panic(fmt.Sprintf("unknown cypher suite: %d", id))
	}
}

func aeadAESGCMTLS13(key, nonceMask []byte) *xorNonceAEAD {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

func aeadChaCha20Poly1305(key, nonceMask []byte) *xorNonceAEAD {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// xorNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

// Seal and Open XOR nonce into the low bytes of nonceMask (the IV). nonce is
// right-aligned: an 8-byte nonce (the RFC 9001 64-bit packet number) lands in
// nonceMask[4:12], a 12-byte nonce (the draft-ietf-quic-multipath §2.4
// path-and-packet-number, with the path ID in the high 32 bits) covers the full
// IV. For a path-0 multipath nonce the leading 4 bytes are zero, so the XOR is
// byte-identical to the 8-byte single-path nonce.
func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	off := aeadNonceLength - len(nonce)
	for i, b := range nonce {
		f.nonceMask[off+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[off+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	off := aeadNonceLength - len(nonce)
	for i, b := range nonce {
		f.nonceMask[off+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[off+i] ^= b
	}

	return result, err
}
