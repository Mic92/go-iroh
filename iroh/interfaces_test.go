package iroh

import (
	"io"
	"net"
	"time"
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

var (
	_ io.ReadWriteCloser = (*Stream)(nil)
	_ io.WriteCloser     = (*SendStream)(nil)
	_ io.Reader          = (*ReceiveStream)(nil)
	_ io.Closer          = (*Conn)(nil)
	_ deadlines          = (*Stream)(nil)
	_ connAddrs          = (*Conn)(nil)
	_ net.Conn           = streamConn{}
)
