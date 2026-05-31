package quic

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

func TestQNTRetryDelay(t *testing.T) {
	initialRTT := 333 * time.Millisecond
	tests := []struct {
		attempt uint8
		want    time.Duration
	}{
		{attempt: 0, want: 33300 * time.Microsecond},
		{attempt: 1, want: 33300 * time.Microsecond},
		{attempt: 2, want: 66600 * time.Microsecond},
		{attempt: 3, want: 133200 * time.Microsecond},
		{attempt: 4, want: 266400 * time.Microsecond},
		{attempt: 5, want: 532800 * time.Microsecond},
		{attempt: 6, want: 1065600 * time.Microsecond},
		{attempt: 7, want: 2 * time.Second},
		{attempt: 8, want: 2 * time.Second},
		{attempt: 9, want: 2 * time.Second},
	}
	for _, tt := range tests {
		if got := qntRetryDelay(tt.attempt, initialRTT); got != tt.want {
			t.Fatalf("qntRetryDelay(%d, %s) = %s, want %s", tt.attempt, initialRTT, got, tt.want)
		}
	}
}

func TestQNTRetryDelayZeroRTT(t *testing.T) {
	if got := qntRetryDelay(3, 0); got != 0 {
		t.Fatalf("qntRetryDelay(3, 0) = %s, want 0", got)
	}
}

func TestQNTArmNextRetryDeadline(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	addr := netip.MustParseAddrPort("198.51.100.1:1234")
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	now := monotime.Now()
	initialRTT := 333 * time.Millisecond
	st := c.qntLocalState()
	st.mu.Lock()
	st.sentProbes = map[[8]byte]netip.AddrPort{challenge: addr}
	st.probeAttempts = map[netip.AddrPort]uint8{addr: qntMaxProbeAttempts - 1}
	st.mu.Unlock()

	deadline, ok := c.qntArmNextRetry(now, initialRTT)
	if !ok {
		t.Fatal("qntArmNextRetry = false, want true")
	}
	want := now.Add(qntRetryDelay(0, initialRTT))
	if deadline != want || c.qntNextRetryDeadline() != want {
		t.Fatalf("retry deadline = %v stored %v, want %v", deadline, c.qntNextRetryDeadline(), want)
	}
}

func TestQNTArmNextRetryDeadlineRequiresSentProbe(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	addr := netip.MustParseAddrPort("198.51.100.1:1234")
	now := monotime.Now()
	st := c.qntLocalState()
	st.mu.Lock()
	st.probeAttempts = map[netip.AddrPort]uint8{addr: qntMaxProbeAttempts - 1}
	st.mu.Unlock()

	if deadline, ok := c.qntArmNextRetry(now, time.Second); ok || !deadline.IsZero() {
		t.Fatalf("qntArmNextRetry without sent probe = %v, %v, want zero false", deadline, ok)
	}
}

func TestQNTQueueRetriesAdvancesRetryDeadlineAttempt(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	addr := netip.MustParseAddrPort("198.51.100.1:1234")
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	now := monotime.Now()
	initialRTT := 333 * time.Millisecond
	st := c.qntLocalState()
	st.mu.Lock()
	st.sentProbes = map[[8]byte]netip.AddrPort{challenge: addr}
	st.probeAttempts = map[netip.AddrPort]uint8{addr: qntMaxProbeAttempts - 1}
	st.nextRetry = now
	st.mu.Unlock()

	if !c.qntQueueProbeRetries() {
		t.Fatal("qntQueueProbeRetries = false, want true")
	}
	if got := c.qntRetryAttempt(); got != 1 {
		t.Fatalf("retry attempt = %d, want 1", got)
	}
	if got := c.qntNextRetryDeadline(); !got.IsZero() {
		t.Fatalf("retry deadline after queue = %v, want zero", got)
	}
	if c.qntQueueProbeRetries() {
		t.Fatal("qntQueueProbeRetries with pending retry = true, want false")
	}
	if got := c.qntRetryAttempt(); got != 1 {
		t.Fatalf("retry attempt after duplicate queue = %d, want 1", got)
	}

	st.mu.Lock()
	st.pendingProbes = st.pendingProbes[:0]
	st.sentProbes[[8]byte{8, 7, 6, 5, 4, 3, 2, 1}] = addr
	st.mu.Unlock()
	deadline, ok := c.qntArmNextRetry(now, initialRTT)
	if !ok {
		t.Fatal("second qntArmNextRetry = false, want true")
	}
	want := now.Add(qntRetryDelay(1, initialRTT))
	if deadline != want {
		t.Fatalf("second retry deadline = %v, want %v", deadline, want)
	}
}

func TestQNTArmNextRetryDeadlineNoRetryableProbes(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	now := monotime.Now()

	if deadline, ok := c.qntArmNextRetry(now, time.Second); ok || !deadline.IsZero() {
		t.Fatalf("qntArmNextRetry without probes = %v, %v, want zero false", deadline, ok)
	}

	addr := netip.MustParseAddrPort("198.51.100.1:1234")
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	st := c.qntLocalState()
	st.mu.Lock()
	st.sentProbes = map[[8]byte]netip.AddrPort{challenge: addr}
	st.probeAttempts = map[netip.AddrPort]uint8{addr: 0}
	st.nextRetry = now
	st.mu.Unlock()
	if deadline, ok := c.qntArmNextRetry(now, time.Second); ok || !deadline.IsZero() {
		t.Fatalf("qntArmNextRetry exhausted = %v, %v, want zero false", deadline, ok)
	}
	if got := c.qntNextRetryDeadline(); !got.IsZero() {
		t.Fatalf("stored retry deadline after exhausted = %v, want zero", got)
	}
}

func TestQNTPathResponseClearsRetryDeadlineWhenNoRetryableProbesRemain(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	addr := netip.MustParseAddrPort("198.51.100.1:1234")
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	now := monotime.Now()
	st := c.qntLocalState()
	st.mu.Lock()
	st.sentProbes = map[[8]byte]netip.AddrPort{challenge: addr}
	st.probeAttempts = map[netip.AddrPort]uint8{addr: qntMaxProbeAttempts - 1}
	st.nextRetry = now
	st.mu.Unlock()

	got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, addr)
	if !ok || got != addr {
		t.Fatalf("qntConsumePathResponse = %v, %v, want %v, true", got, ok, addr)
	}
	if deadline := c.qntNextRetryDeadline(); !deadline.IsZero() {
		t.Fatalf("retry deadline after successful response = %v, want zero", deadline)
	}
}

func TestQNTHandleRetryDeadlineSynctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newNegotiatedQNTConn(8, 16)
		addr := netip.MustParseAddrPort("198.51.100.1:1234")
		challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		initialRTT := 100 * time.Millisecond
		st := c.qntLocalState()
		st.mu.Lock()
		st.sentProbes = map[[8]byte]netip.AddrPort{challenge: addr}
		st.probeAttempts = map[netip.AddrPort]uint8{addr: qntMaxProbeAttempts - 1}
		st.mu.Unlock()

		now := monotime.Now()
		if _, ok := c.qntArmNextRetry(now, initialRTT); !ok {
			t.Fatal("qntArmNextRetry = false, want true")
		}
		time.Sleep(qntRetryDelay(0, initialRTT) - time.Nanosecond)
		if c.qntHandleRetryDeadline(monotime.Now()) {
			t.Fatal("qntHandleRetryDeadline before deadline = true, want false")
		}
		time.Sleep(time.Nanosecond)
		if !c.qntHandleRetryDeadline(monotime.Now()) {
			t.Fatal("qntHandleRetryDeadline at deadline = false, want true")
		}
		if got := c.qntPendingProbeAddresses(); len(got) != 1 || got[0] != addr {
			t.Fatalf("pending probes after retry deadline = %v, want [%v]", got, addr)
		}
		if got := c.qntNextRetryDeadline(); !got.IsZero() {
			t.Fatalf("retry deadline after handling = %v, want zero", got)
		}
	})
}
