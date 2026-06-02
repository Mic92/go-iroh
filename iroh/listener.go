package iroh

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Listen returns a [net.Listener] view of e that accepts bidirectional streams
// as [net.Conn] values. The endpoint must already be configured with the ALPNs
// it should accept.
//
// The listener consumes e's incoming accept loop. Do not use it concurrently
// with [Endpoint.Accept], [Endpoint.AcceptIncoming], or [Router].
//
// Closing the listener stops accepting new streams but does not close e or any
// net.Conn values already returned by [StreamListener.Accept].
func (e *Endpoint) Listen(ctx context.Context) *StreamListener {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	l := &StreamListener{
		ep:      e,
		ctx:     ctx,
		cancel:  cancel,
		streams: make(chan net.Conn),
	}
	go l.run()
	return l
}

// StreamListener accepts bidirectional iroh streams as [net.Conn] values.
type StreamListener struct {
	ep     *Endpoint
	ctx    context.Context
	cancel context.CancelFunc

	streams chan net.Conn

	closeOnce sync.Once
	errMu     sync.Mutex
	err       error
}

// Accept waits for and returns the next accepted bidirectional stream.
func (l *StreamListener) Accept() (net.Conn, error) {
	c, ok := <-l.streams
	if !ok {
		return nil, l.acceptErr()
	}
	return c, nil
}

// Close stops accepting new streams. It does not close the underlying endpoint.
func (l *StreamListener) Close() error {
	l.closeOnce.Do(l.cancel)
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
		close(l.streams)
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
	for {
		c, err := conn.AcceptStreamConn(l.ctx)
		if err != nil {
			return
		}
		select {
		case l.streams <- c:
		case <-l.ctx.Done():
			c.Close()
			return
		}
	}
}

func (l *StreamListener) setErr(err error) {
	l.errMu.Lock()
	defer l.errMu.Unlock()
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
