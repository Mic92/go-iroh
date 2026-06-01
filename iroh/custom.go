package iroh

import (
	"context"

	"github.com/tmc/go-iroh/base"
	"github.com/tmc/go-iroh/internal/socket"
)

// CustomDatagram is one datagram received by a [CustomTransport].
type CustomDatagram struct {
	Remote   base.CustomAddr
	Local    base.CustomAddr
	HasLocal bool
	Data     []byte
}

// CustomTransport is a pluggable endpoint transport for custom addresses.
// Implementations own their wire format and exchange datagrams using
// [base.CustomAddr] values advertised in endpoint addresses.
type CustomTransport interface {
	// Serve runs the transport until ctx is done. Each received datagram should
	// be passed to recv. recv reports false when the endpoint is shutting down or
	// its receive queue is full.
	Serve(ctx context.Context, recv func(CustomDatagram) bool)

	// Send sends p to remote. local is nil when qng did not select a specific
	// local custom address for the path.
	Send(remote base.CustomAddr, local *base.CustomAddr, p []byte) bool
}

type customTransportAdapter struct {
	t CustomTransport
}

func (a customTransportAdapter) Serve(ctx context.Context, recv func(socket.CustomDatagram) bool) {
	a.t.Serve(ctx, func(d CustomDatagram) bool {
		return recv(socket.CustomDatagram{
			Remote:   d.Remote,
			Local:    d.Local,
			HasLocal: d.HasLocal,
			Data:     d.Data,
		})
	})
}

func (a customTransportAdapter) Send(remote base.CustomAddr, local *base.CustomAddr, p []byte) bool {
	return a.t.Send(remote, local, p)
}

func customTransportAdapters(custom []CustomTransport) []socket.CustomTransport {
	if len(custom) == 0 {
		return nil
	}
	out := make([]socket.CustomTransport, 0, len(custom))
	for _, t := range custom {
		if t != nil {
			out = append(out, customTransportAdapter{t: t})
		}
	}
	return out
}
