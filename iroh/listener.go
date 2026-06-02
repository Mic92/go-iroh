package iroh

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/tmc/go-iroh/key"
)

// ListenStreams returns a [net.Listener] view of e that accepts bidirectional
// streams as [net.Conn] values. The endpoint must already be configured with
// the ALPNs it should accept.
//
// The listener consumes e's incoming accept loop. Do not use it concurrently
// with [Endpoint.Accept], [Endpoint.AcceptIncoming], or [Router].
//
// Closing the listener stops accepting new streams but does not close e or any
// net.Conn values already returned by [StreamListener.Accept].
func (e *Endpoint) ListenStreams() *StreamListener {
	ctx, cancel := context.WithCancel(context.Background())
	l := &StreamListener{
		ep:      e,
		ctx:     ctx,
		cancel:  cancel,
		streams: make(chan net.Conn),
		done:    make(chan struct{}),
	}
	go l.run()
	return l
}

// StreamListener accepts bidirectional iroh streams as [net.Conn] values.
//
// Each accepted net.Conn is one bidirectional QUIC stream. Multiple accepted
// net.Conn values may come from the same peer connection. Closing an accepted
// net.Conn closes only that stream; closing the StreamListener closes any peer
// connections it has accepted but does not close the underlying endpoint.
type StreamListener struct {
	ep     *Endpoint
	ctx    context.Context
	cancel context.CancelFunc

	streams chan net.Conn
	done    chan struct{}

	closeOnce sync.Once
	errMu     sync.Mutex
	err       error
}

// Accept waits for and returns the next accepted bidirectional stream.
func (l *StreamListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.streams:
		return c, nil
	case <-l.done:
		return nil, l.acceptErr()
	}
}

// Close stops accepting new streams. It does not close the underlying endpoint.
func (l *StreamListener) Close() error {
	l.closeOnce.Do(func() {
		l.setErr(net.ErrClosed)
		l.cancel()
		close(l.done)
	})
	return nil
}

// Addr returns the endpoint's local UDP address.
func (l *StreamListener) Addr() net.Addr {
	return net.UDPAddrFromAddrPort(l.ep.LocalAddr())
}

func (l *StreamListener) run() {
	var wg sync.WaitGroup
	defer func() {
		l.cancel()
		wg.Wait()
		l.closeOnce.Do(func() {
			close(l.done)
		})
	}()
	for {
		conn, err := l.ep.Accept(l.ctx)
		if err != nil {
			l.setErr(err)
			return
		}
		wg.Add(1)
		go func(conn *Conn) {
			defer wg.Done()
			l.acceptStreams(conn)
		}(conn)
	}
}

func (l *StreamListener) acceptStreams(conn *Conn) {
	owner := newListenerConn(conn)
	defer owner.doneAccepting()
	for {
		c, err := conn.AcceptStreamConn(l.ctx)
		if err != nil {
			return
		}
		owner.addStream()
		c = &listenerStreamConn{Conn: c, owner: owner}
		select {
		case l.streams <- c:
		case <-l.done:
			c.Close()
			return
		case <-l.ctx.Done():
			c.Close()
			return
		}
	}
}

type listenerConn struct {
	conn *Conn

	mu        sync.Mutex
	active    int
	accepting bool
	closed    bool
}

func newListenerConn(conn *Conn) *listenerConn {
	return &listenerConn{conn: conn, accepting: true}
}

func (c *listenerConn) addStream() {
	c.mu.Lock()
	c.active++
	c.mu.Unlock()
}

func (c *listenerConn) releaseStream() {
	c.mu.Lock()
	if c.active > 0 {
		c.active--
	}
	c.closeIfIdleLocked()
	c.mu.Unlock()
}

func (c *listenerConn) doneAccepting() {
	c.mu.Lock()
	c.accepting = false
	c.closeIfIdleLocked()
	c.mu.Unlock()
}

func (c *listenerConn) closeIfIdleLocked() {
	if c.closed || c.accepting || c.active != 0 {
		return
	}
	c.closed = true
	c.conn.Close()
}

type listenerStreamConn struct {
	net.Conn
	owner *listenerConn
	once  sync.Once
}

func (c *listenerStreamConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.owner.releaseStream)
	return err
}

func (c *listenerStreamConn) RemoteID() key.EndpointID {
	return c.Conn.(interface{ RemoteID() key.EndpointID }).RemoteID()
}

func (l *StreamListener) setErr(err error) {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	if l.err != nil {
		return
	}
	if l.ctx.Err() != nil || errors.Is(err, context.Canceled) {
		err = net.ErrClosed
	}
	l.err = err
}

func (l *StreamListener) acceptErr() error {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	if l.err != nil {
		return l.err
	}
	return net.ErrClosed
}
