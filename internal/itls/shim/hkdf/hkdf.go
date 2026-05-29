// Package hkdf is a minimal shim for crypto/internal/fips140/hkdf, implementing
// HKDF (RFC 5869) generically over hash.Hash, matching the API the vendored
// crypto/tls key schedule uses.
package hkdf

import (
	"crypto/hmac"
	"hash"
)

// Extract is HKDF-Extract: returns HMAC-Hash(salt, secret).
func Extract[H hash.Hash](h func() H, secret, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, h().Size())
	}
	mac := hmac.New(func() hash.Hash { return h() }, salt)
	mac.Write(secret)
	return mac.Sum(nil)
}

// Expand is HKDF-Expand: expands pseudorandomKey to keyLen bytes using info.
func Expand[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLen int) []byte {
	out := make([]byte, 0, keyLen)
	var counter uint8
	var t []byte
	for len(out) < keyLen {
		counter++
		mac := hmac.New(func() hash.Hash { return h() }, pseudorandomKey)
		mac.Write(t)
		mac.Write([]byte(info))
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
	}
	return out[:keyLen]
}

// Key is Extract followed by Expand.
func Key[H hash.Hash](h func() H, secret, salt []byte, info string, keyLen int) []byte {
	return Expand(h, Extract(h, secret, salt), info, keyLen)
}
