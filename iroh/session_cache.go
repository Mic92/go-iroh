package iroh

import (
	"sync"

	tls "github.com/tmc/go-iroh/internal/itls/tls"
)

// maxTLSTickets is the default upper bound on cached TLS session tickets used
// for 0-RTT connection establishment. It matches the Rust iroh constant
// DEFAULT_MAX_TLS_TICKETS = 8 * 32 (iroh/src/tls.rs:33): roughly 8 tickets for
// each of 32 distinct remote endpoints, an acceptable ~150 KB cache.
const maxTLSTickets = 8 * 32

// SessionCache stores TLS 1.3 session tickets so a repeat dial to a peer can
// resume with 0-RTT early data instead of a fresh handshake. It wraps a
// [tls.ClientSessionCache] with an LRU eviction policy capped at
// [maxTLSTickets] entries.
//
// Entries are bucketed by TLS server name. iroh derives a unique server name
// from each peer's endpoint id (see [ServerName]), so tickets for different
// peers never collide and resuming always targets the correct identity.
//
// A SessionCache is safe for concurrent use. The zero value is not usable; call
// [NewSessionCache].
type SessionCache struct {
	inner tls.ClientSessionCache

	mu   sync.Mutex
	keys map[string]struct{} // server names that currently hold a ticket
}

// NewSessionCache returns a [SessionCache] that retains at most [maxTLSTickets]
// tickets, evicting the least-recently-used entry when full.
func NewSessionCache() *SessionCache {
	return &SessionCache{
		inner: tls.NewLRUClientSessionCache(maxTLSTickets),
		keys:  make(map[string]struct{}),
	}
}

// Get implements [tls.ClientSessionCache]. It returns the cached session for
// sessionKey, if any.
func (c *SessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	return c.inner.Get(sessionKey)
}

// Put implements [tls.ClientSessionCache]. The TLS stack calls it when a server
// issues a session ticket. A nil session removes the entry, matching the
// [tls.ClientSessionCache] contract.
func (c *SessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.inner.Put(sessionKey, cs)
	c.mu.Lock()
	if cs == nil {
		delete(c.keys, sessionKey)
	} else {
		c.keys[sessionKey] = struct{}{}
	}
	c.mu.Unlock()
}

// Len reports the number of distinct server names that have received at least
// one ticket. It is an upper bound on the buckets eligible for 0-RTT resumption
// and exists for tests and diagnostics.
func (c *SessionCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.keys)
}
