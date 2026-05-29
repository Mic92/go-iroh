// Package fipstls12 implements the TLS 1.2 PRF and extended-master-secret
// derivation (RFC 5246 §5, RFC 7627). It is a shim for the GOROOT-private
// crypto/internal/fips140/tls12, using public crypto/hmac and dropping the
// FIPS service-indicator bookkeeping (which has no wire effect).
package fipstls12

import (
	"crypto/hmac"
	"hash"
)

// PRF implements the TLS 1.2 pseudo-random function.
func PRF[H hash.Hash](hashFn func() H, secret []byte, label string, seed []byte, keyLen int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	result := make([]byte, keyLen)
	pHash(hashFn, result, secret, labelAndSeed)
	return result
}

// pHash implements the P_hash function from RFC 5246 §5.
func pHash[H hash.Hash](hashFn func() H, result, secret, seed []byte) {
	newHash := func() hash.Hash { return hashFn() }
	h := hmac.New(newHash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	for len(result) > 0 {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		n := copy(result, b)
		result = result[n:]

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

const masterSecretLength = 48
const extendedMasterSecretLabel = "extended master secret"

// MasterSecret implements the TLS 1.2 extended master secret derivation
// (RFC 7627).
func MasterSecret[H hash.Hash](hashFn func() H, preMasterSecret, transcript []byte) []byte {
	return PRF(hashFn, preMasterSecret, extendedMasterSecretLabel, transcript, masterSecretLength)
}
