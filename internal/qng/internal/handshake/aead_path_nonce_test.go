package handshake

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"testing"

	tls "github.com/tmc/go-iroh/internal/itls/tls"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

// oldRFC9001Nonce is the pre-fix qng nonce: the 64-bit packet number in network
// byte order, with no path qualification (aead.go before stage 5). The
// path-qualified nonce must reduce to exactly this for PathIDZero, so the
// single-path stack stays byte-identical.
func oldRFC9001Nonce(pn protocol.PacketNumber) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(pn))
	return b[:]
}

// TestPutPathNonceLayout proves the draft-ietf-quic-multipath §2.4 byte layout:
// PathIDZero collapses to the RFC 9001 packet-number nonce (single-path
// unchanged), and a non-zero path folds its id into the high 32 bits, never
// colliding with path 0 for the same packet number.
func TestPutPathNonceLayout(t *testing.T) {
	pns := []protocol.PacketNumber{0, 1, 5, 42, 0xdead_beef, 1<<62 - 1}

	for _, pn := range pns {
		var buf [12]byte
		got := putPathNonce(buf[:], protocol.PathIDZero, pn)
		// Path 0: must be the 8-byte RFC 9001 nonce, byte-for-byte.
		if want := oldRFC9001Nonce(pn); !bytes.Equal(got, want) {
			t.Errorf("putPathNonce(path=0, pn=%d) = % x, want RFC 9001 nonce % x", pn, got, want)
		}
		if len(got) != 8 {
			t.Errorf("putPathNonce(path=0) len = %d, want 8 (single-path nonce width)", len(got))
		}
	}

	for _, pn := range pns {
		var buf0, buf1 [12]byte
		n0 := putPathNonce(buf0[:], protocol.PathIDZero, pn)
		n1 := putPathNonce(buf1[:], protocol.PathID(1), pn)

		// Path 1 must be 12 bytes: [path_id(4)] [pn(8)].
		if len(n1) != 12 {
			t.Fatalf("putPathNonce(path=1) len = %d, want 12 (path-and-packet-number width)", len(n1))
		}
		// High 32 bits carry the path id, low 64 bits carry the packet number.
		if pid := binary.BigEndian.Uint32(n1[:4]); pid != 1 {
			t.Errorf("path 1 nonce high 32 bits = %d, want path id 1", pid)
		}
		if low := binary.BigEndian.Uint64(n1[4:]); low != uint64(pn) {
			t.Errorf("path 1 nonce low 64 bits = %d, want pn %d", low, pn)
		}

		// The fix: path 0 and path 1 must not produce the same nonce value for the
		// same packet number. Compare in the common 96-bit space (left-pad path 0).
		var pad0 [12]byte
		copy(pad0[12-len(n0):], n0)
		if bytes.Equal(pad0[:], n1) {
			t.Errorf("path 0 and path 1 nonces collide for pn=%d: % x", pn, n1)
		}
	}
}

// TestPutPathNonceHighPathID exercises the full 32-bit path id range so the high
// word is laid out in network byte order, as the draft requires.
func TestPutPathNonceHighPathID(t *testing.T) {
	var buf [12]byte
	n := putPathNonce(buf[:], protocol.PathIDMax, 7)
	if pid := binary.BigEndian.Uint32(n[:4]); pid != uint32(protocol.PathIDMax) {
		t.Errorf("high 32 bits = %#x, want %#x", pid, uint32(protocol.PathIDMax))
	}
	if low := binary.BigEndian.Uint64(n[4:]); low != 7 {
		t.Errorf("low 64 bits = %d, want 7", low)
	}
}

// newTestUpdatableAEAD builds a 1-RTT AEAD with a fixed traffic secret, so a
// sender and receiver under test share the same key/IV (multipath uses one
// key/IV across all paths; only the nonce differs).
func newTestUpdatableAEAD(t *testing.T) *updatableAEAD {
	t.Helper()
	suite := getCipherSuite(tls.TLS_AES_128_GCM_SHA256)
	secret := hkdfExpandLabel(crypto.SHA256, []byte("path-nonce-test-secret-00000000"), []byte{}, "quic key", suite.Hash.Size())
	a := newUpdatableAEAD(nil, nil, nil, protocol.Version1)
	a.SetWriteKey(suite, secret)
	a.SetReadKey(suite, secret)
	return a
}

// TestPathQualifiedSealCiphertextDiffers proves the end-to-end fix through the
// real AEAD: sealing the same plaintext at the same packet number on path 0 and
// path 1 yields different ciphertext (no AEAD nonce reuse across paths), while
// the path-0 ciphertext round-trips and decrypts on path 0.
func TestPathQualifiedSealCiphertextDiffers(t *testing.T) {
	const pn = protocol.PacketNumber(5)
	plaintext := []byte("multipath says hello over a path")
	ad := []byte("associated-header-data")

	seal := func(pid protocol.PathID) []byte {
		a := newTestUpdatableAEAD(t)
		dst := make([]byte, 0, len(plaintext)+a.Overhead())
		return append([]byte(nil), a.Seal(dst, plaintext, pid, pn, ad)...)
	}

	ct0 := seal(protocol.PathIDZero)
	ct1 := seal(protocol.PathID(1))
	if bytes.Equal(ct0, ct1) {
		t.Fatalf("path 0 and path 1 produced identical ciphertext for pn=%d: nonce reuse not fixed", pn)
	}

	// Path 0 must round-trip (single-path correctness preserved).
	opener := newTestUpdatableAEAD(t)
	dec, err := opener.Open(make([]byte, 0, len(plaintext)), ct0, 0, protocol.PathIDZero, pn, protocol.KeyPhaseZero, ad)
	if err != nil {
		t.Fatalf("open path 0 ciphertext: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Fatalf("path 0 round-trip = %q, want %q", dec, plaintext)
	}

	// Path 1 must round-trip under its own path id, and must NOT open as path 0
	// (the nonce mismatch is what protects against cross-path confusion).
	openerMP := newTestUpdatableAEAD(t)
	dec1, err := openerMP.Open(make([]byte, 0, len(plaintext)), ct1, 0, protocol.PathID(1), pn, protocol.KeyPhaseZero, ad)
	if err != nil {
		t.Fatalf("open path 1 ciphertext on path 1: %v", err)
	}
	if !bytes.Equal(dec1, plaintext) {
		t.Fatalf("path 1 round-trip = %q, want %q", dec1, plaintext)
	}
	openerCross := newTestUpdatableAEAD(t)
	if _, err := openerCross.Open(make([]byte, 0, len(plaintext)), ct1, 0, protocol.PathIDZero, pn, protocol.KeyPhaseZero, ad); err == nil {
		t.Fatalf("path 1 ciphertext wrongly opened as path 0: cross-path nonce not isolated")
	}
}

// TestPathQualifiedSealPath0Identical proves that sealing on PathIDZero is
// byte-identical to sealing with the pre-fix 8-byte packet-number nonce: the
// path-0 send path is unchanged. It reconstructs the pre-fix behavior by sealing
// the raw GCM with the IV-XOR'd 8-byte nonce directly.
func TestPathQualifiedSealPath0Identical(t *testing.T) {
	plaintext := []byte("single path payload, unchanged")
	ad := []byte("ad")

	for _, pn := range []protocol.PacketNumber{0, 1, 5, 99, 0xabcd} {
		a := newTestUpdatableAEAD(t)
		got := a.Seal(make([]byte, 0, len(plaintext)+a.Overhead()), plaintext, protocol.PathIDZero, pn, ad)

		// Pre-fix reference: build the same AEAD and seal with the 8-byte nonce
		// (the old code path), which xorNonceAEAD XORs into the low 64 bits of the
		// IV — exactly what putPathNonce(path=0) does.
		ref := newTestUpdatableAEAD(t)
		want := ref.sendAEAD.Seal(make([]byte, 0, len(plaintext)+ref.aeadOverhead), oldRFC9001Nonce(pn), plaintext, ad)

		if !bytes.Equal(got, want) {
			t.Errorf("path 0 seal at pn=%d = % x, want pre-fix nonce ciphertext % x", pn, got, want)
		}
	}
}
