package iroh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/tmc/go-iroh/base"
)

// ProtocolHandler handles connections accepted for a single ALPN. A [Router]
// dispatches each incoming connection to the handler registered for its
// negotiated ALPN.
//
// Accept is called in its own goroutine for every accepted connection; it should
// run for the lifetime of the connection and return when done. A returned error
// is logged. A handler must not panic; a panic is recovered and logged and stops
// the router's accept loop (the protocol-router wire contract, iroh/DESIGN.md
// §2). It is the Go analog of the Rust ProtocolHandler trait
// (iroh/src/protocol.rs:228).
type ProtocolHandler interface {
	// Accept handles an accepted connection. ctx is cancelled when the router
	// shuts down.
	Accept(ctx context.Context, conn *Conn) error
}

// ShutdownHandler is an optional interface a [ProtocolHandler] may implement to
// run cleanup when its [Router] shuts down. The router calls Shutdown on every
// registered handler that implements it before closing the endpoint, giving
// handlers a chance to close connections gracefully. It mirrors the Rust
// ProtocolHandler::shutdown hook (iroh/src/protocol.rs:284).
type ShutdownHandler interface {
	// Shutdown is called once when the router is shutting down.
	Shutdown(ctx context.Context)
}

// IncomingFilterOutcome is the decision an [IncomingFilter] returns for an
// incoming connection. It mirrors the Rust IncomingFilterOutcome
// (iroh/src/protocol.rs).
type IncomingFilterOutcome int

const (
	// FilterAccept accepts the connection and dispatches it to a handler.
	FilterAccept IncomingFilterOutcome = iota
	// FilterReject refuses the connection.
	//
	// In this build the pre-handshake Incoming controls (Retry/Reject/Ignore)
	// are not yet exposed by the endpoint, so FilterReject closes the connection
	// after accept rather than refusing it pre-handshake. FilterRetry and
	// FilterIgnore degrade to the same close; see iroh/DESIGN.md O6.
	FilterReject
	// FilterRetry asks the peer to retry (emit a QUIC Retry packet). Degraded:
	// see FilterReject.
	FilterRetry
	// FilterIgnore silently drops the connection. Degraded: see FilterReject.
	FilterIgnore
)

// Incoming describes an incoming connection to an [IncomingFilter]. In this
// build it carries only the verified remote id and negotiated ALPN, available
// after the handshake; the pre-handshake fields of the Rust Incoming arrive with
// a later slice (iroh/DESIGN.md O6).
type Incoming struct {
	// RemoteID is the verified endpoint id of the peer.
	RemoteID base.EndpointId
	// ALPN is the negotiated ALPN protocol.
	ALPN []byte
}

// IncomingFilter decides whether to accept each incoming connection. It is
// called synchronously in the accept loop and must be fast and non-blocking. It
// mirrors the Rust IncomingFilter (iroh/src/protocol.rs).
type IncomingFilter func(*Incoming) IncomingFilterOutcome

// RouterBuilder accumulates protocol registrations for a [Router]. Create one
// with [NewRouter], register handlers with [RouterBuilder.Accept], optionally set
// an [IncomingFilter], then start the router with [RouterBuilder.Spawn].
type RouterBuilder struct {
	ep       *Endpoint
	handlers map[string]ProtocolHandler
	filter   IncomingFilter
	logger   *slog.Logger
}

// NewRouter returns a [RouterBuilder] for ep.
func NewRouter(ep *Endpoint) *RouterBuilder {
	return &RouterBuilder{ep: ep, handlers: make(map[string]ProtocolHandler)}
}

// Accept registers h to handle connections whose negotiated ALPN exactly equals
// alpn. Registering the same ALPN twice replaces the earlier handler. It returns
// the builder for chaining.
func (b *RouterBuilder) Accept(alpn []byte, h ProtocolHandler) *RouterBuilder {
	b.handlers[string(alpn)] = h
	return b
}

// IncomingFilter sets the filter consulted for each incoming connection. It
// returns the builder for chaining.
func (b *RouterBuilder) IncomingFilter(f IncomingFilter) *RouterBuilder {
	b.filter = f
	return b
}

// Logger sets the logger used for handler errors and recovered panics. The
// default is [slog.Default]. It returns the builder for chaining.
func (b *RouterBuilder) Logger(l *slog.Logger) *RouterBuilder {
	b.logger = l
	return b
}

// Spawn registers every protocol's ALPN on the endpoint, starts the accept loop,
// and returns the running [Router]. The endpoint must not already be listening
// (do not pass [WithALPNs] to [Bind] when using a Router). Spawn returns an error
// if registering the ALPNs fails.
func (b *RouterBuilder) Spawn() (*Router, error) {
	logger := b.logger
	if logger == nil {
		logger = slog.Default()
	}

	alpns := make([][]byte, 0, len(b.handlers))
	for a := range b.handlers {
		alpns = append(alpns, []byte(a))
	}
	if err := b.ep.SetALPNs(alpns); err != nil {
		return nil, fmt.Errorf("iroh: router spawn: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &Router{
		ep:       b.ep,
		handlers: b.handlers,
		filter:   b.filter,
		logger:   logger,
		cancel:   cancel,
		ctx:      ctx,
	}
	r.wg.Add(1)
	go r.acceptLoop(ctx)
	return r, nil
}

// Router accepts incoming connections on an [Endpoint] and dispatches each to
// the [ProtocolHandler] registered for its negotiated ALPN. Start one with
// [RouterBuilder.Spawn]; stop it with [Router.Shutdown]. It is the Go analog of
// the Rust Router (iroh/src/protocol.rs:97).
//
// Dispatch is by exact ALPN bytes. One goroutine runs the accept loop; each
// accepted connection is handled in a child goroutine with a context derived
// from the router's. A panic in a handler goroutine is recovered, logged, and
// stops the accept loop (the protocol-router wire contract, iroh/DESIGN.md §2).
type Router struct {
	ep       *Endpoint
	handlers map[string]ProtocolHandler
	filter   IncomingFilter
	logger   *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	shutdown bool
}

// Endpoint returns the endpoint the router accepts on.
func (r *Router) Endpoint() *Endpoint { return r.ep }

// IsShutdown reports whether the router has been shut down.
func (r *Router) IsShutdown() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.shutdown
}

// acceptLoop accepts connections until ctx is cancelled, the endpoint closes, or
// a handler goroutine panics. Each connection is dispatched in a child
// goroutine.
func (r *Router) acceptLoop(ctx context.Context) {
	defer r.wg.Done()
	// panicked fires when a handler goroutine recovers a panic; the loop breaks
	// so a misbehaving handler cannot keep accepting traffic.
	panicked := make(chan struct{})
	var panicOnce sync.Once

	for {
		select {
		case <-ctx.Done():
			return
		case <-panicked:
			return
		default:
		}

		conn, err := r.ep.Accept(ctx)
		if err != nil {
			// A cancelled context or a closed endpoint ends the loop cleanly.
			if ctx.Err() != nil || errors.Is(err, ErrEndpointClosed) {
				return
			}
			// A failed accept (e.g. a peer aborting the handshake) is logged and
			// the loop continues. The endpoint surfaces a hard close via the
			// checks above.
			r.logger.Warn("router: accept failed", "err", err)
			continue
		}

		handler, ok := r.handlers[string(conn.ALPN())]
		if !ok {
			r.logger.Warn("router: no handler for ALPN", "alpn", string(conn.ALPN()))
			conn.CloseWithError(0, "unsupported ALPN")
			continue
		}

		if r.filter != nil {
			outcome := r.filter(&Incoming{RemoteID: conn.RemoteID(), ALPN: conn.ALPN()})
			if outcome != FilterAccept {
				// Degraded: pre-handshake Retry/Reject/Ignore are not exposed yet
				// (DESIGN.md O6), so any non-accept outcome closes the connection.
				conn.CloseWithError(0, "rejected by filter")
				continue
			}
		}

		r.wg.Add(1)
		go func(conn *Conn, h ProtocolHandler) {
			defer r.wg.Done()
			defer func() {
				if v := recover(); v != nil {
					r.logger.Error("router: handler panicked", "alpn", string(conn.ALPN()), "panic", v)
					conn.CloseWithError(0, "handler panic")
					panicOnce.Do(func() { close(panicked) })
				}
			}()
			if err := h.Accept(ctx, conn); err != nil {
				r.logger.Warn("router: handler returned error", "alpn", string(conn.ALPN()), "err", err)
			}
		}(conn, handler)
	}
}

// Shutdown stops the router: it cancels the accept loop and all handler
// contexts, calls Shutdown on every registered handler that implements
// [ShutdownHandler], closes the endpoint, and waits for the accept loop and
// handler goroutines to finish or ctx to be done. It is idempotent and the Go
// analog of the Rust Router::shutdown (iroh/src/protocol.rs:429).
func (r *Router) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	if r.shutdown {
		r.mu.Unlock()
		return nil
	}
	r.shutdown = true
	r.mu.Unlock()

	// Stop accepting and cancel handler contexts.
	r.cancel()

	// Give handlers a chance to close connections gracefully before the endpoint
	// force-closes them. Rust awaits all protocol shutdown futures
	// concurrently; do the same so one slow protocol does not block the rest.
	var shutdownWG sync.WaitGroup
	for _, h := range r.handlers {
		if sh, ok := h.(ShutdownHandler); ok {
			shutdownWG.Add(1)
			go func(sh ShutdownHandler) {
				defer shutdownWG.Done()
				sh.Shutdown(ctx)
			}(sh)
		}
	}
	handlersDone := make(chan struct{})
	go func() {
		shutdownWG.Wait()
		close(handlersDone)
	}()
	select {
	case <-handlersDone:
	case <-ctx.Done():
		return ctx.Err()
	}

	closeErr := r.ep.Close(ctx)

	// Wait for the accept loop and handler goroutines, bounded by ctx.
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return closeErr
}
