package iroh

import (
	"io"
	"net"
	"time"

	"github.com/tmc/go-iroh/key"
)

type deadlines interface {
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type connAddrs interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type peerIDConn interface {
	RemoteID() key.EndpointID
}

var (
	_ io.ReadWriteCloser = (*Stream)(nil)
	_ io.WriteCloser     = (*SendStream)(nil)
	_ io.Reader          = (*ReceiveStream)(nil)
	_ io.Closer          = (*Conn)(nil)
	_ io.Closer          = (*PkarrPublisher)(nil)
	_ deadlines          = (*Stream)(nil)
	_ connAddrs          = (*Conn)(nil)
	_ net.Conn           = streamConn{}
	_ peerIDConn         = streamConn{}
	_ net.Listener       = (*StreamListener)(nil)
	_ ProtocolHandler    = ProtocolHandlerFunc(nil)
	_ AddressPublisher   = AddressPublisherFunc(nil)
	_ AddressResolver    = AddressResolverFunc(nil)
)
